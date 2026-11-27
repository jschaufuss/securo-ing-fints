"""Parse and validate ING FinTS depot holdings."""

import re
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP, localcontext

from ing_common import BankSyncError, _account_type, _digest, _require_result, _text


def _purchase_cost(section, quantity, currency):
    """Read an unambiguous FinTS structured 70E HOLD cost for UNIT holdings.

    The leading digits are line numbers, not part of either field. Unknown,
    duplicate, percentage or foreign-currency data is deliberately ignored.
    """
    fields = []
    current = None
    for line in section:
        if line.startswith(':'):
            if current is not None:
                fields.append(current)
            current = [line[len(':70E::HOLD//'):]] if line.startswith(':70E::HOLD//') else None
        elif current is not None:
            current.append(line)
    if current is not None:
        fields.append(current)

    candidates = []
    for lines in fields:
        # The leading '1' identifies the first structured line, and STK
        # identifies a per-unit security; other formats need different maths.
        first = [line for line in lines if re.fullmatch(r'1STK(?:\+[^+]*){0,5}', line)]
        second = [line for line in lines if line.startswith('2')]
        if len(first) != 1 or len(second) != 1:
            continue
        match = re.fullmatch(r'2(\d+,\d*)\+([A-Z]{3})(?:\+(?:\d+,\d*)?)?', second[0])
        if not match or match.group(2) != currency:
            continue
        if len(match.group(1).replace(',', '')) > 15:
            continue
        price = Decimal(match.group(1).replace(',', '.'))
        if price <= 0 or quantity <= 0:
            continue
        try:
            with localcontext() as ctx:
                ctx.prec = 40
                cost = (price * quantity).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
        except InvalidOperation:
            continue
        if Decimal('0') < cost < Decimal('10000000000000'):
            candidates.append(cost)
    # Multiple independent HOLD fields are ambiguous even if they agree.
    return candidates[0] if len(candidates) == 1 and len(fields) == 1 else None


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
        isin = name = currency = quantity = total = unit_price = price_currency = None
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
            match = re.fullmatch(r':90B::MRKT//ACTU/([A-Z]{3})(\d+),(\d*)', line)
            if match:
                price_currency = match.group(1)
                unit_price = Decimal(match.group(2) + '.' + (match.group(3) or '0'))
        if not isin or not name or quantity is None or total is None or currency is None:
            raise BankSyncError('ING depot statement is incomplete; holdings were not imported')
        if quantity.as_tuple().exponent < -6 or total.as_tuple().exponent < -6:
            raise BankSyncError('ING depot precision exceeds Securo limits; holdings were not imported')
        row = {'external_id': _digest(salt, 'hold-', depot_key, isin), 'name': name,
                        'type': 'investment', 'currency': currency,
                        'quantity': format(quantity, 'f'), 'current_value': format(total, 'f'),
                        'isin': isin, 'account_external_id': depot_key,
                        'account_name': 'ING Direct Depot', 'trades': None}
        purchase_cost = _purchase_cost(section, quantity, currency)
        if purchase_cost is not None:
            row['purchase_price'] = format(purchase_cost, 'f')
        if unit_price is not None and price_currency == currency:
            row['unit_price'] = format(unit_price, 'f')
        elif quantity > 0:
            # UNIT positions only: this is an indicative per-unit valuation in
            # the holding currency, not necessarily an exchange-traded quote.
            # Securo accepts at most six fractional and twelve integer digits.
            try:
                with localcontext() as ctx:
                    ctx.prec = 40
                    derived = (total / quantity).quantize(Decimal('0.000001'), rounding=ROUND_HALF_UP)
                if derived < Decimal('1000000000000'):
                    row['unit_price'] = format(derived, 'f')
            except InvalidOperation:
                pass  # Preserve the position even if an indicative price cannot fit.
        results.append(row)
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
            body = getattr(segment, 'holdings', None)
            if isinstance(body, bytes):
                body = body.decode('iso-8859-1')
            lines = [line.strip() for line in body.splitlines() if line.strip()] if isinstance(body, str) else []
            markers = (':16R:GENL', ':16S:GENL', ':16R:ADDINFO', ':16S:ADDINFO')
            if not (lines and lines[-1] == '-' and all(lines.count(m) == 1 for m in markers) and
                    [lines.index(m) for m in markers] == sorted(lines.index(m) for m in markers)):
                raise BankSyncError('ING returned an incomplete depot statement; holdings were not changed')
            # A valid envelope alone does not establish that every position is
            # inside the holdings section. Do not silently ignore misplaced FINs.
            start, end = lines.index(':16S:GENL'), lines.index(':16R:ADDINFO')
            if any(not start < i < end for i, line in enumerate(lines)
                   if line in (':16R:FIN', ':16S:FIN')):
                raise BankSyncError('ING returned an invalid depot statement; holdings were not changed')
            rows.extend(_parse_depot_statement(body, account, salt))
        results.extend(rows)
    if len(results) > 5000 or len({row['external_id'] for row in results}) != len(results):
        raise BankSyncError('ING depot positions are duplicated or exceed Securo limits')
    return results


