"""Isolated experiment: a fixed offset is not a verified ING decoding rule.

These fixtures never feed the plugin or update Securo. The first records the
hypothetical example; the second shows why the same rule cannot be generalized.
"""
import unittest
from decimal import Decimal


def experimental_cost(raw_amount: Decimal) -> Decimal:
    return raw_amount - Decimal('2000')


class TestExperimentalOffset(unittest.TestCase):
    def test_hypothetical_example(self):
        self.assertEqual(experimental_cost(Decimal('2271.62')), Decimal('271.62'))

    def test_ordinary_amount_produces_invalid_negative_cost(self):
        self.assertEqual(experimental_cost(Decimal('42.75')), Decimal('-1957.25'))


if __name__ == '__main__':
    unittest.main()
