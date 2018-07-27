#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

from trezor.crypto import chacha20poly1305 as ChaCha20Poly1305, monero, random


def encrypt(key, plaintext, associated_data=None):
    """
    Uses ChaCha20Poly1305 for encryption
    :param key:
    :param plaintext:
    :param associated_data:
    :return: iv, ciphertext, tag
    """
    nonce = random.bytes(12)
    cipher = ChaCha20Poly1305(key, nonce)
    if associated_data:
        cipher.auth(associated_data)
    ciphertext = cipher.encrypt(plaintext)
    tag = cipher.finish()
    return nonce, ciphertext + tag, b""


def decrypt(key, iv, ciphertext, tag=None, associated_data=None):
    """
    ChaCha20Poly1305 decryption
    :param key:
    :param iv:
    :param ciphertext:
    :param tag:
    :param associated_data:
    :return:
    """
    cipher = ChaCha20Poly1305(key, iv)
    if associated_data:
        cipher.auth(associated_data)
    exp_tag, ciphertext = ciphertext[-16:], ciphertext[:-16]
    plaintext = cipher.decrypt(ciphertext)
    tag = cipher.finish()
    if not monero.ct_equals(tag, exp_tag):
        raise ValueError("tag invalid")

    return plaintext


def encrypt_pack(key, plaintext, associated_data=None):
    b = encrypt(key, plaintext, associated_data)
    return b[0] + b[1]


def decrypt_pack(key, ciphertext):
    cp = memoryview(ciphertext)
    return decrypt(key, cp[:12], cp[12:], None)
