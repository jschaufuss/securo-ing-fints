"""Translate ING transaction data to the Securo provider contract."""

from collections import Counter

from ing_common import BankSyncError, _as_iso_day, _digest, _money, _text

MAX_TX = 20_000

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


