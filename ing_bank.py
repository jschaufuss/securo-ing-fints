"""Read-only ING Germany FinTS provider for Securo >=0.20.0.

Plugin API: https://github.com/securo-finance/securo/blob/v0.20.0/docs/plugins/bank-provider-plugins.md
No transfers or payments; no HTTP endpoint. Securo runs Plugin.sync itself.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import re
import secrets as pysecrets
from collections import Counter
from decimal import Decimal, InvalidOperation
from zoneinfo import ZoneInfo

ING_BANK_CODE = '50010517'
ING_SERVER = 'https://fints.ing.de/fints/'
CONTRACT = 1
MAX_TX = 20_000


class NeedsAuth(Exception):
    """Securo should pause polling until credentials / approval are refreshed."""


class RateLimited(Exception):
    """Securo should retry on its next scheduled interval."""


class BankSyncError(Exception):
    """Bank or data-format failure with a non-sensitive message."""


def _text(value, size=500) -> str:
    if isinstance(value, (list, tuple)):
        value = ' '.join(_text(item, size) for item in value if item is not None)
    elif isinstance(value, bytes):
        value = value.decode('utf-8', errors='replace')
    return ' '.join(str(value or '').split())[:size]


def _money(value) -> Decimal:
    if hasattr(value, 'amount'):
        value = value.amount
    try:
        v = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise BankSyncError('ING returned an unreadable amount; nothing was imported') from None
    if not v.is_finite():
        raise BankSyncError('ING returned an invalid amount; nothing was imported')
    return v


def _as_iso_day(value) -> str:
    if isinstance(value, dt.datetime):
        return value.date().isoformat()
    if isinstance(value, dt.date):
        return value.isoformat()
    if isinstance(value, str):
        try:
            return dt.date.fromisoformat(value[:10]).isoformat()
        except ValueError:
            pass
    raise BankSyncError('ING booking has no valid posting date; nothing was imported')


def _digest(salt: str, prefix: str, *values) -> str:
    # HMAC prevents revealing the IBAN and preserves IDs across syncs.
    content = '\x1f'.join(str(value) for value in values).encode('utf-8')
    return prefix + hmac.new(bytes.fromhex(salt), content, hashlib.sha256).hexdigest()[:40]


def _transaction_rows(items, salt: str, account_id: str, *, status='posted') -> list[dict]:
    """Normalize mt940 and fints.models.Transaction rows to Securo contract 1.

    Truly identical rows without a bank transaction ID can only be identified by
    their occurrence number; reordering identical bank records is impossible to
    disambiguate without an actual bank-assigned immutable ID.
    """
    prepared = []
    for item in items:
        raw = getattr(item, 'data', None)
        if not isinstance(raw, dict):
            raise BankSyncError('ING returned an unknown transaction format; nothing was imported')
        date = _as_iso_day(raw.get('entry_date') or raw.get('booking_date') or raw.get('bookingDate') or raw.get('date'))
        amount = _money(raw.get('amount'))
        desc = _text(raw.get('purpose') or raw.get('transaction_details') or
                     raw.get('remittance_information') or raw.get('applicant_name') or
                     raw.get('extra_details') or 'ING transaction', 500)
        payee = _text(raw.get('applicant_name') or raw.get('recipient_name') or raw.get('counterparty_name'), 200)
        references = [_text(raw.get(k), 100) for k in (
            'transaction_id', 'bank_reference', 'end_to_end_reference', 'customer_reference', 'id')]
        references = [r for r in references if r.upper() not in ('', 'NOTPROVIDED', 'NONREF', 'NONE')]
        # The fingerprint includes the business fields even when a reference is present.
        fingerprint = (account_id, date, str(amount), desc, payee, *references)
        prepared.append((fingerprint, {
            'description': desc,
            'amount': format(abs(amount), 'f'),
            'date': date,
            'type': 'credit' if amount >= 0 else 'debit',
            'currency': _text(getattr(raw.get('amount'), 'currency', None) or raw.get('currency') or 'EUR', 3).upper(),
            'status': status,
            **({'payee': payee} if payee else {}),
        }))
    occurrence = Counter()
    rows = []
    # Sorting by content makes duplicate occurrence IDs independent of API order.
    for fingerprint, row in sorted(prepared, key=lambda pair: pair[0]):
        n = occurrence[fingerprint]
        occurrence[fingerprint] += 1
        row['external_id'] = _digest(salt, 'tx-' if status == 'posted' else 'pending-', *fingerprint, n)
        rows.append(row)
    if len(rows) > MAX_TX:
        raise BankSyncError('Too many ING transactions for one Securo synchronization; shorten history window')
    return rows


def _account_type(product: str) -> str:
    p = product.casefold()
    if any(word in p for word in ('extra-konto', 'extrakonto', 'tagesgeld', 'spar', 'savings')):
        return 'savings'
    if any(word in p for word in ('depot', 'investment', 'wertpapier')):
        return 'investment'
    return 'checking'


def _get_bank_info(bank) -> dict:
    value = bank.get_information() or {}
    return {str(a.get('iban', '')).replace(' ', ''): a
            for a in value.get('accounts', []) if isinstance(a, dict) and a.get('iban')}


def _require_result(value, *, stage: str):
    # Do not save a pending challenge as a successful sync; never initiate payments.
    if value is None:
        raise BankSyncError(f'ING returned no {stage}; nothing was imported')
    if value.__class__.__name__ in ('NeedTANResponse', 'NeedRetryResponse'):
        raise NeedsAuth('ING requires approval in the banking app; automated FinTS sync is paused')
    return value


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


def _parse_depot_statement(body, account, salt):
    """Read complete MT535 positions without logging or approximating bank values."""
    if isinstance(body, bytes):
        body = body.decode('iso-8859-1')
    if not isinstance(body, str):
        raise BankSyncError('Unsupported ING depot statement')
    lines = body.splitlines()
    sections = []
    current = None
    for line in lines:
        line = line.strip()
        if line == ':16R:FIN':
            if current is not None:
                raise BankSyncError('Incomplete ING depot statement')
            current = []
        elif line == ':16S:FIN':
            if current is None:
                raise BankSyncError('Incomplete ING depot statement')
            sections.append(current)
            current = None
        elif current is not None:
            current.append(line)
    if current is not None:
        raise BankSyncError('Incomplete ING depot statement')
    if not sections:
        return []
    depot_key = _digest(salt, 'depot-', getattr(account, 'blz', ''),
                        getattr(account, 'accountnumber', ''), getattr(account, 'subaccount', ''))
    results = []
    for section in sections:
        isin = name = currency = quantity = total = None
        for index, line in enumerate(section):
            match = re.fullmatch(r':35B:ISIN\s+([A-Z]{2}[A-Z0-9]{9}[0-9])(?:\s+(.*))?', line)
            if match:
                isin = match.group(1)
                parts = []
                if match.group(2):
                    parts.append(match.group(2))
                for follow in section[index + 1:]:
                    if follow.startswith(':') or follow.startswith('-'):
                        break
                    if follow and not follow.startswith('/DE/'):
                        parts.append(follow)
                name = _text(parts[-1] if parts else '', 255)
            match = re.fullmatch(r':93B::AGGR//UNIT/(\d+),(\d*)', line)
            if match:
                quantity = Decimal(match.group(1) + '.' + (match.group(2) or '0'))
            match = re.fullmatch(r':19A::HOLD//([A-Z]{3})(\d+),(\d*)', line)
            if match:
                currency = match.group(1)
                total = Decimal(match.group(2) + '.' + (match.group(3) or '0'))
        if not isin or not name or quantity is None or total is None or currency is None:
            raise BankSyncError('ING depot statement is incomplete; holdings were not imported')
        if quantity.as_tuple().exponent < -6 or total.as_tuple().exponent < -6:
            raise BankSyncError('ING depot precision exceeds Securo limits; holdings were not imported')
        results.append({'external_id': _digest(salt, 'hold-', depot_key, isin), 'name': name,
                        'type': 'investment', 'currency': currency,
                        'quantity': format(quantity, 'f'), 'current_value': format(total, 'f'),
                        'isin': isin, 'account_external_id': depot_key,
                        'account_name': 'ING Direct Depot', 'trades': None})
    return results


def _holdings_rows(bank, entries, metadata, salt):
    """Read every discovered depot completely; never archive on an uncertain response."""
    candidates = [a for a in entries if _account_type(_text(metadata.get(
        _text(getattr(a, 'iban', '')).replace(' ', '').upper(), {}).get('product_name'))) == 'investment']
    if not candidates:
        return None
    results = []
    for account in candidates:
        segments = _require_result(bank.get_depot_statements(account), stage='depot holdings')
        if not segments:
            return None
        rows = []
        for segment in segments:
            rows.extend(_parse_depot_statement(getattr(segment, 'holdings', None), account, salt))
        if not rows:
            return None
        results.extend(rows)
    if len(results) > 5000 or len({row['external_id'] for row in results}) != len(results):
        raise BankSyncError('ING depot positions are duplicated or exceed Securo limits')
    return results


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
            for acc in listed:
                iban = _text(getattr(acc, 'iban', '')).replace(' ', '').upper()
                if not iban:
                    raise BankSyncError('An ING account has no stable IBAN; nothing was imported')
                acc_id = _digest(salt, 'ing-', iban)
                product = _text(metadata.get(iban, {}).get('product_name') or 'ING account', 180)
                if _account_type(product) == 'investment':
                    continue
                currency = _text(metadata.get(iban, {}).get('currency') or 'EUR', 3).upper()
                if len(currency) != 3 or not currency.isalpha():
                    raise BankSyncError('Unexpected account currency; nothing was imported')
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
