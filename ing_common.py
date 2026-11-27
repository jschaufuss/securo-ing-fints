"""Shared validation, identifiers and errors for the ING provider."""

import datetime as dt
import hashlib
import hmac
from decimal import Decimal, InvalidOperation

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


def _require_result(value, *, stage: str):
    # Do not save a pending challenge as a successful sync; never initiate payments.
    if value is None:
        raise BankSyncError(f'ING returned no {stage}; nothing was imported')
    if value.__class__.__name__ in ('NeedTANResponse', 'NeedRetryResponse'):
        raise NeedsAuth('ING requires approval in the banking app; automated FinTS sync is paused')
    return value


def _account_type(product: str) -> str:
    p = product.casefold()
    if any(word in p for word in ('extra-konto', 'extrakonto', 'tagesgeld', 'spar', 'savings')):
        return 'savings'
    if any(word in p for word in ('depot', 'investment', 'wertpapier')):
        return 'investment'
    return 'checking'


