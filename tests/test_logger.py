# -*- coding: utf-8 -*-
import logging
import os
import tempfile
import unittest

from logger import TransactionFileHandler


class TransactionFileHandlerTests(unittest.TestCase):
    def test_each_ppse_transaction_gets_an_individual_file(self):
        with tempfile.TemporaryDirectory() as directory:
            logger = logging.getLogger(f"tx-test-{id(self)}")
            logger.setLevel(logging.DEBUG)
            logger.propagate = False
            handler = TransactionFileHandler(directory)
            handler.setFormatter(logging.Formatter("%(message)s"))
            logger.addHandler(handler)
            try:
                logger.info("registration outside transaction")
                logger.debug(
                    "APDU EMU>REA CAPDU SELECT len=20: "
                    "00A404000E325041592E5359532E444446303100"
                )
                logger.info("first transaction payload")
                logger.info("Session epoch opened: 2 [guard=IDLE]")
                logger.debug(
                    "APDU EMU>REA CAPDU SELECT len=20: "
                    "00A404000E325041592E5359532E444446303100"
                )
                logger.info("second transaction payload")
                logger.info("RelayServer stopped")
            finally:
                handler.close()
                logger.removeHandler(handler)

            paths = sorted(os.path.join(directory, name) for name in os.listdir(directory))
            self.assertEqual(len(paths), 2)
            with open(paths[0], encoding="utf-8") as stream:
                first = stream.read()
            with open(paths[1], encoding="utf-8") as stream:
                second = stream.read()

            self.assertIn("first transaction payload", first)
            self.assertNotIn("registration outside transaction", first)
            self.assertNotIn("second transaction payload", first)
            self.assertIn("second transaction payload", second)
            self.assertNotIn("first transaction payload", second)


if __name__ == "__main__":
    unittest.main()
