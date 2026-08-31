#!/usr/bin/env python3
"""Reproduce the RSA-SM3 signatures in test_suite_psa_crypto.data."""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

import hashlib
import re
from pathlib import Path

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15, pss


DATA_FILE = (Path(__file__).parents[1] / "suites" /
             "test_suite_psa_crypto.data")
MESSAGE_TEST = "PSA sign/verify message: RSA PKCS#1 v1.5 SM3"
PKCS1_TEST = ("PSA verify message: RSA PKCS#1 v1.5 SM3, "
              "PyCryptodome signature")
PSS_TEST = "PSA verify message: RSA PSS SM3, PyCryptodome signature"


class SM3:
    """The subset of the PyCryptodome hash-object interface used here."""

    oid = "1.2.156.10197.1.401"
    digest_size = 32

    def __init__(self, data=b""):
        self._hash = hashlib.new("sm3", data)

    def update(self, data):
        """Add data to the hash."""
        self._hash.update(data)

    def digest(self):
        """Return the hash value."""
        return self._hash.digest()

    def new(self, data=b""):
        """Return a new SM3 hash object."""
        return type(self)(data)


def quoted_hex_fields(test_name):
    """Extract the byte-string arguments of a named test case."""
    data = DATA_FILE.read_text(encoding="utf-8")
    test_body = data.split(test_name + "\n", 1)[1]
    function_line = test_body.splitlines()[1]
    return [bytes.fromhex(value)
            for value in re.findall(r'"([0-9a-f]+)"', function_line)]


def main():
    """Generate the signatures and check them against the test vectors."""
    private_key_der, message = quoted_hex_fields(MESSAGE_TEST)
    key = RSA.import_key(private_key_der)

    pkcs1_signature = pkcs1_15.new(key).sign(SM3(message))

    salt = bytes(range(32))

    def fixed_salt(length):
        assert length == len(salt)
        return salt

    pss_signature = pss.new(key, salt_bytes=len(salt),
                            rand_func=fixed_salt).sign(SM3(message))

    expected_pkcs1_signature = quoted_hex_fields(PKCS1_TEST)[2]
    expected_pss_signature = quoted_hex_fields(PSS_TEST)[2]
    assert pkcs1_signature == expected_pkcs1_signature
    assert pss_signature == expected_pss_signature

    print("SM3(message):", SM3(message).digest().hex())
    print("RSA PKCS#1 v1.5-SM3 signature:", pkcs1_signature.hex())
    print("RSA-PSS-SM3 salt:", salt.hex())
    print("RSA-PSS-SM3 signature:", pss_signature.hex())


if __name__ == "__main__":
    main()
