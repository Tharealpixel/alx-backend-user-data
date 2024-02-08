#!/usr/bin/env python3
"""
Encrypting passwors
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """ Returns a salted, hashed password, which is byte string """
    encoded = password.encode()
    hashed = bcrypt.hashpw(encoded, bcrypt.gensalt())

    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """ Validates the provided password matchethe hashed password """
    valid = False
    encoded = password.encode()
    if bcrypt.checkpw(encoded, hashed_password):
        valid = True
    return valid
