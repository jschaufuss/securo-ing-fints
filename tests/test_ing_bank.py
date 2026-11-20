import json
import re
import sys
import types
import unittest
from datetime import date
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ing_bank as p


class Amount:
    def __init__(self, amount, currency='EUR'):
        self.amount = Decimal(amount)
        self.currency = currency


class Bank:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.init_tan_response = None
        self.entries = [SimpleNamespace(iban='DE12123456780000000001'), SimpleNamespace(iban='DE12123456780000000002')]

    def __enter__(self):
        # python-fints opens the dialog but does not return the client.
        return None

    def __exit__(self, *args):
        return False

    def get_sepa_accounts(self):
        return self.entries

    def get_information(self):
        return {'accounts': [
            {'iban': self.entries[0].iban, 'product_name': 'ING Girokonto', 'currency': 'EUR'},
            {'iban': self.entries[1].iban, 'product_name': 'ING Extra-Konto', 'currency': 'EUR'},
        ]}

    def get_balance(self, entry):
        return SimpleNamespace(amount=Amount('2300.34' if entry == self.entries[0] else '4100.32'))

    def get_transactions(self, entry, **kwargs):
        return [SimpleNamespace(data={
            'date': date(2026, 11, 17), 'purpose': 'REWE',
            'amount': Amount('-34.78'), 'applicant_name': 'REWE'}),
            SimpleNamespace(data={
            'date': date(2026, 11, 17), 'purpose': 'Gehalt',
            'amount': Amount('2600.00'), 'applicant_name': 'Arbeitgeber'})]

    def deconstruct(self):
        return b'not-an-actual-bank-blob'


FakeTAN = type("NeedTANResponse", (), {})


def context(saved=None, cfg=None):
    return SimpleNamespace(secrets={
        'login': 'test-login', 'pin': '12345', **(saved or {})},
        config={'product_id': 'registered-test-id', **(cfg or {})})


class TestPlugin(unittest.TestCase):
    def setUp(self):
        fake = types.ModuleType('fints')
        client = types.ModuleType('fints.client')
        client.FinTS3PinTanClient = Bank
        client.NeedTANResponse = FakeTAN
        self.mods = patch.dict(sys.modules, {'fints': fake, 'fints.client': client})
        self.mods.start()
        self.addCleanup(self.mods.stop)

    def test_auth_errors_are_distinguished_without_exposing_bank_details(self):
        for kind, expected in [('FinTSClientPINError', 'FinTSClientPINError'),
                               ('FinTSClientTemporaryAuthError', '3938'),
                               ('FinTSSCARequiredError', '9075')]:
            error = type(kind, (Exception,), {})
            def fail(**kwargs):
                raise error('sensitive bank details')
            with self.subTest(kind=kind), self.assertRaises(p.NeedsAuth) as caught:
                p._sync({}, context(), factory=fail)
            self.assertIn(expected, str(caught.exception))
            self.assertNotIn('sensitive bank details', str(caught.exception))

    def test_balance_diagnostics_only_include_numeric_codes(self):
        class Response:
            def find_segments(self, query):
                self.query = query
                return [SimpleNamespace(responses=[SimpleNamespace(code='9210'),
                                                   SimpleNamespace(code='secret')])]
        response = Response()
        self.assertEqual(p._balance_codes(response), '9210')
        self.assertEqual(response.query, ('HIRMG', 'HIRMS'))

    def test_contract_accounts(self):
        result = p._sync({}, context(), factory=Bank, today=date(2026, 11, 18))
        self.assertEqual(result['data']['contract'], 1)
        self.assertEqual(len(result['data']['accounts']), 2)
        self.assertEqual({x['type'] for x in result['data']['accounts']}, {'checking', 'savings'})
        self.assertIsNone(result['data']['holdings'])
        self.assertEqual(result['data']['accounts'][0]['masked_number'], '0001')
        self.assertEqual(result['data']['accounts'][0]['balance'], '2300.34')
        self.assertEqual(result['data']['accounts'][0]['transactions'][0]['type'], 'debit')
        self.assertEqual(result['data']['accounts'][0]['transactions'][0]['amount'], '34.78')
        self.assertFalse('iban' in json.dumps(result, ensure_ascii=False).lower())
        self.assertFalse('12345' in json.dumps(result))

    def test_account_selection_filters_and_rejects_missing_iban(self):
        selected = p._sync({}, context(saved={'account_ibans': 'DE12 1234 5678 0000 0000 02'}), factory=Bank)
        self.assertEqual(len(selected['data']['accounts']), 1)
        self.assertEqual(selected['data']['accounts'][0]['masked_number'], '0002')
        with self.assertRaisesRegex(p.BankSyncError, 'not returned'):
            p._sync({}, context(saved={'account_ibans': 'DE12123456780000000003'}), factory=Bank)

    def test_pending_transactions_are_separate_and_labelled(self):
        class PendingBank(Bank):
            def get_transactions(self, entry, **kwargs):
                booked = super().get_transactions(entry, **kwargs)
                if kwargs.get('include_pending'):
                    return booked + [SimpleNamespace(data={'date': date(2026, 11, 18), 'purpose': 'Pending', 'amount': Amount('-3.78')})]
                return booked
        result = p._sync({}, context(), factory=PendingBank)
        rows = result['data']['accounts'][0]['transactions']
        self.assertEqual([row['status'] for row in rows].count('pending'), 1)
        self.assertEqual([row['status'] for row in rows].count('posted'), 2)
        self.assertTrue(next(row for row in rows if row['status'] == 'pending')['external_id'].startswith('pending-'))

    def test_pending_balance_requires_a_bank_value(self):
        with self.assertRaisesRegex(p.BankSyncError, 'did not provide a pending balance'):
            p._sync({}, context(cfg={'balance_mode': 'pending'}), factory=Bank)
        with self.assertRaisesRegex(p.BankSyncError, 'must be booked or pending'):
            p._sync({}, context(cfg={'balance_mode': 'invalid'}), factory=Bank)
        class PendingBank(Bank):
            def get_balance(self, entry):
                self._pending_balance = SimpleNamespace(amount=Decimal('2.43'), as_mt940_Balance=lambda: SimpleNamespace(amount=Amount('2.43')))
                return super().get_balance(entry)
        result = p._sync({}, context(cfg={'balance_mode': 'pending'}), factory=PendingBank)
        self.assertEqual(result['data']['accounts'][0]['balance'], '2.43')
        self.assertEqual(result['data']['accounts'][1]['balance'], '4100.32')

    def test_booking_date_before_value_date(self):
        row = SimpleNamespace(data={
            'date': date(2026, 11, 15), 'entry_date': date(2026, 11, 17),
            'purpose': 'Kartenzahlung', 'amount': Amount('-4.20')})
        records = p._transaction_rows([row], 'ab' * 32, 'acc')
        self.assertEqual(records[0]['date'], '2026-11-17')

    def test_deterministic_ids_with_saved_salt(self):
        one = p._sync({}, context(), factory=Bank, today=date(2026, 11, 18))
        two = p._sync({}, context(saved=one['secrets']), factory=Bank, today=date(2026, 11, 18))
        self.assertEqual(one['data'], two['data'])
        self.assertEqual(one['secrets']['id_salt'], two['secrets']['id_salt'])
        self.assertEqual(one['data']['accounts'][0]['external_id'], one['data']['accounts'][0]['stable_external_id'])

    def test_incremental_window(self):
        observed = {}
        class Observing(Bank):
            def get_transactions(self, entry, **kwargs):
                observed['since'] = kwargs['start_date']
                return super().get_transactions(entry, **kwargs)
        p._sync({'since': '2026-11-04'}, context(), factory=Observing, today=date(2026, 11, 18))
        self.assertEqual(observed['since'], date(2026, 11, 4))

    def test_reject_empty_accounts(self):
        class Empty(Bank):
            def get_sepa_accounts(self): return []
        with self.assertRaises(p.BankSyncError):
            p._sync({}, context(), factory=Empty, today=date(2026, 11, 18))

    def test_tan_pauses_sync(self):
        class Challenge(Bank):
            def __init__(self, **kw):
                super().__init__(**kw)
                self.init_tan_response = FakeTAN()
        with self.assertRaises(p.NeedsAuth):
            p._sync({}, context(), factory=Challenge, today=date(2026, 11, 18))

    def test_tan_in_balances(self):
        class Challenge(Bank):
            def get_balance(self, entry): return FakeTAN()
        with self.assertRaises(p.NeedsAuth):
            p._sync({}, context(), factory=Challenge, today=date(2026, 11, 18))

    def test_holdings_missing_keep_none(self):
        result = p._sync({}, context(cfg={'holdings_enabled': 'yes'}), factory=Bank, today=date(2026, 11, 18))
        self.assertIsNone(result['data']['holdings'])

    def test_depot_is_read_independently_of_selected_cash_accounts(self):
        statement = (':16R:FIN\n:35B:ISIN DE0000000001\n/DE/EXAMPLE\nExample fund\n'
                     ':93B::AGGR//UNIT/2,500000\n:19A::HOLD//EUR123,45\n:16S:FIN\n')
        class DepotBank(Bank):
            def __init__(self, **kw):
                super().__init__(**kw)
                self.depot = SimpleNamespace(iban='DE12123456780000000003', accountnumber='123', subaccount='00', blz='50010517')
                self.entries.append(self.depot)
            def get_information(self):
                result = super().get_information()
                result['accounts'].append({'iban': self.depot.iban, 'product_name': 'Direct Depot'})
                return result
            def get_balance(self, entry):
                if entry == self.depot:
                    raise AssertionError('A depot must not be queried for a cash balance')
                return super().get_balance(entry)
            def get_depot_statements(self, account):
                self.assert_depot = account == self.depot
                return [SimpleNamespace(holdings=statement.encode('ascii'))]
        result = p._sync({}, context(saved={'account_ibans': 'DE12123456780000000001'},
                                     cfg={'holdings_enabled': 'yes'}), factory=DepotBank)
        self.assertEqual(len(result['data']['accounts']), 1)
        holding = result['data']['holdings'][0]
        self.assertEqual((holding['name'], holding['quantity'], holding['current_value'], holding['currency']),
                         ('Example fund', '2.500000', '123.45', 'EUR'))
        self.assertTrue(holding['account_external_id'].startswith('depot-'))

    def _two_depot_bank(self):
        statement = (':16R:FIN\n:35B:ISIN DE0000000001\n/DE/EXAMPLE\nExample fund\n'
                     ':93B::AGGR//UNIT/2,500000\n:19A::HOLD//EUR123,45\n:16S:FIN\n')
        class TwoDepotBank(Bank):
            def __init__(self, **kw):
                super().__init__(**kw)
                self.full = SimpleNamespace(iban='DE12123456780000000003', accountnumber='123', subaccount='00', blz='50010517')
                self.empty = SimpleNamespace(iban='DE12123456780000000004', accountnumber='124', subaccount='00', blz='50010517')
                self.entries += [self.full, self.empty]
                self.queried = []
            def get_information(self):
                result = super().get_information()
                result['accounts'] += [{'iban': self.full.iban, 'product_name': 'Direkt-Depot'},
                                       {'iban': self.empty.iban, 'product_name': 'Direkt-Depot'}]
                return result
            def get_depot_statements(self, account):
                self.queried.append(account.iban)
                # ING answers an empty depot with 3010 "Kein Depotbestand vorhanden": no segments.
                return [SimpleNamespace(holdings=statement.encode('ascii'))] if account == self.full else []
        return TwoDepotBank

    def test_empty_depot_does_not_discard_another_depots_positions(self):
        result = p._sync({}, context(cfg={'holdings_enabled': 'yes'}), factory=self._two_depot_bank())
        holdings = result['data']['holdings']
        self.assertIsNotNone(holdings)
        self.assertEqual([(h['isin'], h['quantity']) for h in holdings], [('DE0000000001', '2.500000')])

    def test_selected_depot_limits_which_depots_are_read(self):
        bank_cls = self._two_depot_bank()
        made = []
        def factory(**kw):
            made.append(bank_cls(**kw))
            return made[-1]
        result = p._sync({}, context(saved={'account_ibans': 'DE12123456780000000001,DE12123456780000000004'},
                                     cfg={'holdings_enabled': 'yes'}), factory=factory)
        self.assertEqual(made[0].queried, ['DE12123456780000000004'])
        # The only selected depot is empty: holdings stay untouched (None), not archived ([]).
        self.assertIsNone(result['data']['holdings'])

    def test_depot_parser_rejects_incomplete_positions(self):
        account = SimpleNamespace(accountnumber='123', subaccount='00', blz='50010517')
        self.assertEqual(p._parse_depot_statement(':16R:GENL\n:16S:GENL\n', account, 'ab' * 32), [])
        with self.assertRaises(p.BankSyncError):
            p._parse_depot_statement(':16R:FIN\n:35B:ISIN DE0000000001\n:16S:FIN\n', account, 'ab' * 32)

    def test_bad_history(self):
        with self.assertRaises(p.BankSyncError):
            p._sync({}, context(cfg={'history_days': '400'}), factory=Bank)

    def test_missing_secrets(self):
        with self.assertRaises(p.NeedsAuth):
            p._sync({}, context(saved={'pin': ''}), factory=Bank)

    def test_bad_amount(self):
        with self.assertRaises(p.BankSyncError):
            p._money('nan')

    def test_duplicate_occurrence(self):
        t = SimpleNamespace(data={'date': date(2026, 11, 17), 'purpose': 'Test', 'amount': Amount('-2.35')})
        salt = 'ab' * 32
        a = p._transaction_rows([t, t], salt, 'account')
        self.assertEqual(len({v['external_id'] for v in a}), 2)
        b = p._transaction_rows([t, t], salt, 'account')
        self.assertEqual(a, b)

    def test_no_floats_returned(self):
        data = p._sync({}, context(), factory=Bank, today=date(2026, 11, 18))
        def walk(x):
            if isinstance(x, dict):
                for y in x.values(): walk(y)
            elif isinstance(x, list):
                for y in x: walk(y)
            else:
                self.assertFalse(isinstance(x, float))
        walk(data)

    def test_manifest(self):
        manifest = json.loads((Path(__file__).resolve().parents[1] / 'securo-plugin.json').read_text())
        self.assertEqual(manifest['min_securo_version'], '0.20.0')
        self.assertEqual(manifest['runtime']['entrypoint'], 'ing_bank:plugin')
        self.assertEqual(manifest['network'][0]['host'], 'fints.ing.de')
        self.assertEqual(manifest['contributes']['integrations'][0]['provides'], ['accounts','transactions','holdings'])
        self.assertTrue(re.match(r'^[a-z0-9-]+/[a-z0-9-]+$', manifest['id']))

if __name__ == '__main__':
    unittest.main()
