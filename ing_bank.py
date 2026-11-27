"""Read-only ING Germany FinTS provider for Securo >=0.20.0.

Plugin API: https://github.com/securo-finance/securo/blob/v0.20.0/docs/plugins/bank-provider-plugins.md
No transfers or payments; no HTTP endpoint. Securo runs Plugin.sync itself.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import secrets as pysecrets
from zoneinfo import ZoneInfo

from ing_common import BankSyncError, NeedsAuth, RateLimited, _account_type, _as_iso_day, _digest, _money, _require_result, _text
from ing_transactions import MAX_TX, _transaction_rows
from ing_depot import _holdings_rows, _parse_depot_statement

ING_BANK_CODE = '50010517'
ING_SERVER = 'https://fints.ing.de/fints/'
CONTRACT = 1


def _get_bank_info(bank) -> dict:
    value = bank.get_information() or {}
    return {str(a.get('iban', '')).replace(' ', ''): a
            for a in value.get('accounts', []) if isinstance(a, dict) and a.get('iban')}


def _balance_codes(response):
    """Only retain FinTS response codes, never bank messages or account data."""
    codes = set()
    for segment in response.find_segments(('HIRMG', 'HIRMS')):
        for item in segment.responses:
            code = str(item.code)
            if len(code) == 4 and code.isascii() and code.isdigit():
                codes.add(code)
    return ','.join(sorted(codes)) or 'none'


def _balance_reason(response):
    for segment in response.find_segments(('HIRMG', 'HIRMS')):
        for item in segment.responses:
            message = str(getattr(item, 'text', '') or '').lower()
            if 'depot' in message and ('saldo' in message or 'kont' in message):
                return 'depot'
            if 'keine gültige kontoverbindung' in message or 'keine gueltige kontoverbindung' in message:
                return 'invalid-account'
            if 'auftragsart' in message and 'konto' in message and 'nicht möglich' in message:
                return 'unsupported-account'
    return 'unclassified'


def _settings(params, context):
    config = context.config or {}
    secret = context.secrets or {}
    login = _text(secret.get('login'))
    pin = str(secret.get('pin') or '')
    product_id = _text(config.get('product_id'))
    if not login or not pin or not product_id:
        raise NeedsAuth('ING login, PIN and registered FinTS product ID are required')
    days = 85
    if config.get('history_days'):
        try:
            days = int(config['history_days'])
        except (ValueError, TypeError):
            raise BankSyncError('History days must be a whole number from 1 to 89') from None
    if not 1 <= days <= 89:
        raise BankSyncError('History days must be between 1 and 89')
    salt = secret.get('id_salt') or pysecrets.token_hex(32)
    if len(salt) != 64:
        raise BankSyncError('Saved ID salt is invalid; do not reset it or account IDs will change')
    try:
        bytes.fromhex(salt)
    except ValueError:
        raise BankSyncError('Saved ID salt is invalid') from None
    return login, pin, product_id, days, salt


def _sync(params, context, *, factory=None, today=None) -> dict:
    login, pin, product_id, days, salt = _settings(params, context)
    today = today or dt.datetime.now(ZoneInfo('Europe/Berlin')).date()
    start = today - dt.timedelta(days=days)
    if params.get('since'):
        try:
            requested = dt.date.fromisoformat(params['since'])
        except ValueError:
            raise BankSyncError('Invalid Securo sync window') from None
        start = max(start, requested)
    if start > today:
        start = today
    balance_mode = str(context.config.get('balance_mode') or 'booked').strip().lower()
    if balance_mode not in ('booked', 'pending'):
        raise BankSyncError('Balance mode must be booked or pending')
    from fints.client import FinTS3PinTanClient, NeedTANResponse
    if factory is None:
        class DiagnosedClient(FinTS3PinTanClient):
            def get_depot_statements(self, account):
                from fints.segments.depot import HKWPD5, HKWPD6
                with self._get_dialog() as dialog:
                    command = self._find_highest_supported_command(HKWPD5, HKWPD6)
                    return self._fetch_with_touchdowns(
                        dialog,
                        lambda point: command(account=command._fields['account'].type.from_sepa_account(account), touchdown_point=point),
                        lambda responses: responses, 'HIWPD')

            def _get_balance(self, command_seg, response):
                balance = super()._get_balance(command_seg, response)
                if balance is None:
                    raise BankSyncError(f'ING returned no account balance; FinTS codes: {_balance_codes(response)}; reason: {_balance_reason(response)}')
                for segment in response.response_segments(command_seg, 'HISAL'):
                    self._pending_balance = getattr(segment, 'balance_pending', None)
                return balance
        factory = DiagnosedClient
    identity = hashlib.sha256((login + '\x00' + product_id).encode()).hexdigest()
    restored = None
    if context.secrets.get('fints_identity') == identity and context.secrets.get('fints_client_blob'):
        try:
            restored = base64.b64decode(context.secrets['fints_client_blob'], validate=True)
        except (ValueError, TypeError):
            raise BankSyncError('Invalid saved FinTS client state') from None
    kwargs = {'bank_identifier': ING_BANK_CODE, 'user_id': login, 'pin': pin,
              'server': ING_SERVER, 'product_id': product_id}
    if restored:
        kwargs['from_data'] = restored
    try:
        client = factory(**kwargs)
        with client:
            bank = client
            if isinstance(getattr(bank, 'init_tan_response', None), NeedTANResponse):
                raise NeedsAuth('ING requires app approval to start the FinTS session')
            listed = _require_result(bank.get_sepa_accounts(), stage='account list')
            if not listed:
                raise BankSyncError('ING returned no SEPA accounts; existing accounts are unchanged')
            all_accounts = list(listed)
            selection = str(context.secrets.get('account_ibans') or '').strip()
            if selection:
                selected = {''.join(part.split()).upper() for part in selection.replace(';', ',').split(',')}
                if any(not iban or not iban.isascii() or not iban.isalnum() or not 15 <= len(iban) <= 34 for iban in selected):
                    raise BankSyncError('Invalid account selection; enter complete IBANs separated by commas')
                available = {str(getattr(acc, 'iban', '') or '').replace(' ', '').upper() for acc in listed}
                if not selected <= available:
                    raise BankSyncError('At least one selected IBAN was not returned by ING; nothing was imported')
                listed = [acc for acc in listed if str(getattr(acc, 'iban', '') or '').replace(' ', '').upper() in selected]
            metadata = _get_bank_info(bank)
            accounts = []
            seen_account_ids = set()
            for acc in listed:
                iban = _text(getattr(acc, 'iban', '')).replace(' ', '').upper()
                if not iban:
                    raise BankSyncError('An ING account has no stable IBAN; nothing was imported')
                acc_id = _digest(salt, 'ing-', iban)
                if acc_id in seen_account_ids:
                    raise BankSyncError('ING returned the same account more than once; nothing was imported')
                seen_account_ids.add(acc_id)
                product = _text(metadata.get(iban, {}).get('product_name') or 'ING account', 180)
                if _account_type(product) == 'investment':
                    continue
                currency = _text(metadata.get(iban, {}).get('currency') or 'EUR', 3).upper()
                if len(currency) != 3 or not currency.isalpha():
                    raise BankSyncError('Unexpected account currency; nothing was imported')
                # Never reuse the preceding account's pending balance.
                bank._pending_balance = None
                balance_obj = _require_result(bank.get_balance(acc), stage='account balance')
                if balance_mode == 'pending' and _account_type(product) == 'checking':
                    pending_balance = getattr(bank, '_pending_balance', None)
                    if pending_balance is None or getattr(pending_balance, 'amount', None) is None:
                        raise BankSyncError('ING did not provide a pending balance for the checking account; no data was imported')
                    balance_obj = pending_balance.as_mt940_Balance()
                bal = _money(getattr(balance_obj, 'amount', balance_obj))
                tx_objs = _require_result(bank.get_transactions(acc, start_date=start, end_date=today), stage='transactions')
                rows = _transaction_rows(tx_objs, salt, acc_id)
                if _account_type(product) == 'checking':
                    combined = _require_result(bank.get_transactions(acc, start_date=start, end_date=today, include_pending=True), stage='pending transactions')
                    if len(combined) < len(tx_objs) or _transaction_rows(combined[:len(tx_objs)], salt, acc_id) != rows:
                        raise BankSyncError('ING returned inconsistent transaction lists; nothing was imported')
                    rows += _transaction_rows(combined[len(tx_objs):], salt, acc_id, status='pending')
                accounts.append({
                    'external_id': acc_id,
                    'stable_external_id': acc_id,
                    'name': product,
                    'type': _account_type(product),
                    'balance': format(bal, 'f'),
                    'currency': currency,
                    'institution_name': 'ING Deutschland',
                    'institution_external_id': 'ing-de',
                    'institution_logo': 'bank',
                    'masked_number': iban[-4:],
                    'transactions': rows,
                })
            if len(accounts) > 500 or sum(len(a['transactions']) for a in accounts) > MAX_TX:
                raise BankSyncError('ING result exceeds Securo batch limits; reduce history_days')
            # Opt-in. Never archive all assets on a transient unsupported FinTS response.
            include_holdings = str(context.config.get('holdings_enabled', '')).strip().lower() in ('yes', 'true', '1')
            holdings = _holdings_rows(bank, all_accounts, metadata, salt) if include_holdings else None
        # Avoid persisting PIN in log files: serialized client state goes to encrypted Securo plugin vault.
        try:
            client_data = base64.b64encode(client.deconstruct()).decode('ascii')
        except Exception:
            client_data = None
    except (NeedsAuth, BankSyncError):
        raise
    except Exception as exc:
        # Never expose bank server messages: they may include IBANs, TAN data or secrets.
        cls = type(exc).__name__
        if cls == 'FinTSClientPINError':
            raise NeedsAuth('ING rejected FinTS dialog initialization (FinTSClientPINError); the cause is not necessarily an incorrect PIN') from None
        if cls == 'FinTSClientTemporaryAuthError':
            raise NeedsAuth('ING reports that FinTS access is temporarily locked (3938); contact ING before retrying') from None
        if cls == 'FinTSSCARequiredError':
            raise NeedsAuth('ING requires strong customer authentication (9075); this plugin cannot complete an interactive approval') from None
        if cls in ('FinTSConnectionError', 'FinTSNoResponseError', 'TimeoutError',
                   'ConnectTimeout', 'ReadTimeout', 'ConnectionError'):
            raise RateLimited('ING FinTS connection is temporarily unavailable') from None
        tb = exc.__traceback__
        while tb and tb.tb_next:
            tb = tb.tb_next
        location = f'{tb.tb_frame.f_code.co_name}:{tb.tb_lineno}' if tb else 'unknown'
        name = getattr(exc, 'name', None) if isinstance(exc, AttributeError) else None
        detail = f', attribute {name}' if isinstance(name, str) and name.isidentifier() and len(name) <= 80 else ''
        raise BankSyncError(f'ING FinTS sync failed ({cls}, {location}{detail}); no data was changed') from None

    bank_secrets = {'id_salt': salt, 'fints_identity': identity}
    if client_data:
        bank_secrets['fints_client_blob'] = client_data
    # holdings None means not read, not "empty depot".
    return {
        'state': {'last_read_day': today.isoformat()},
        'secrets': bank_secrets,
        'data': {'contract': CONTRACT, 'accounts': accounts, 'holdings': holdings},
    }


class Plugin:
    def sync(self, params: dict, context) -> dict:
        return _sync(params or {}, context)


plugin = Plugin()
