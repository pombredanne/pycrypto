# -*- coding: utf-8 -*-
#
#  PublicKey/RSA_PKCS1.py : RSA PKCS#1 v2.1 implementation
#
# Copyright (C) 2008  Dwayne C. Litzenberger <dlitz@dlitz.net>
#
# =======================================================================
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# =======================================================================

"""RSA PKCS#1 v2.1 implementation.

For information about PKCS#1, see:

    http://www.rsa.com/rsalabs/node.asp?id=2125
    http://tools.ietf.org/html/rfc3447
"""

__revision__ = "$Id$"

import struct

from Crypto import Random
from Crypto.Random.random import StrongRandom
from Crypto.Util.strxor import strxor
from Crypto.Util.number import long_to_bytes, bytes_to_long, ceil_div, floor_div
from Crypto.PublicKey import RSA

from Crypto.Util.python_compat import *

# Mode constants.  We choose numbers that are different from those in
# block_template.c, so that people don't try to do "RSA in CBC mode" or some
# other such nonsense.
#MODE_PRIMITIVE = 0x100           # No padding
MODE_OAEP_ENCRYPT = 0x102        # PKCS#1 v2.1 encryption/decryption (use this for new programs)
MODE_OAEP_SIGN = 0x103           # PKCS#1 v2.1 signing/verification  (use this for new programs)
#MODE_PKCS1_v1_5_ENCRYPT = 0x104  # PKCS#1 v1.5 encryption/decryption (from the PKCS#1 v2.1 spec)
#MODE_PKCS1_v1_5_SIGN = 0x105     # PKCS#1 v1.5 signing/verification  (from the PKCS#1 v2.1 spec)

#def os2ip(s):
#    """Octet-string-to-integer primitive.
#
#    Returns an integer given an octet string.
#    """
#    if not isinstance(s, str):
#        raise TypeError("argument 1 expected str, not %r" % (type(s),))
#    return bytes_to_long(s)
#
#def i2osp(x, bytes):
#    """Integer-to-octet-string primitive.
#
#    Returns an octet string of a specified length given an integer.
#    """
#    if not isinstance(x, (int, long)):
#        raise TypeError("argument 1 expected an integer, not %r" % (type(x),))
#    if not isinstance(bytes, (int, long)):
#        raise TypeError("argument 2 expected an integer, not %r" % (type(bytes),))
#    if bytes < 1:
#        raise ValueError("number of bytes must be positive")
#    s = long_to_bytes(x, bytes)
#    if len(s) != bytes:
#        raise ValueError("integer too large")
#    return s

def MGF1(seed, num_bytes, digestmod):
    """PKCS#1's "MGF1" mask generation function."""
    if not isinstance(num_bytes, (int, long)):
        raise TypeError("argument 2 must be an integer, not %r" % (type(num_bytes),))
    if num_bytes < 0:
        raise ValueError("number of bytes must not be negative")
    elif num_bytes == 0:
        return ""
    h = digestmod.new(seed)
    num_blocks = ceil_div(num_bytes, h.digest_size)
    if num_blocks > 2**32:
        raise OverflowError("mask too long")
    retval = []
    for counter in xrange(num_blocks):
        bh = h.copy()
        bh.update(struct.pack("!L", counter))
        block = bh.digest()
        retval.append(block)
    return "".join(retval)[:num_bytes]

def EME_OAEP_encode(k, message, label, digestmod, mgf, randfunc=None, seed=None):
    """Generate a padded message ready for RSA encryption.

    This performs EME-OAEP encoding according to RSA PKCS#1 v2.1.
    """
    # Type-check arguments
    if not isinstance(k, (int, long)):
        raise TypeError("argument 1 must be an integer, not %r" % (type(k),))
    if not isinstance(message, str):
        raise TypeError("argument 2 must be an octet string, not %r" % (type(message),))
    if not isinstance(label, str):
        raise TypeError("argument 3 must be an octet string, not %r" % (type(label),))

    # Random number generator
    if randfunc is None:
        randfunc = Random.new().read

    # PKCS#1 says we should check that the labal length is less than the input
    # limitation for the hash function, but we don't bother, because that
    # should be huge (2**61-1 octets for SHA1, and more for SHA256).  If we
    # want to apply input length limits to hash functions, then we should do it
    # in the hash function implementations themselves.

    # Check the message length
    hLen = digestmod.digest_size
    if len(message) > k - 2*hLen - 2:
        raise OverflowError("message too long")

    # Hash the label
    lHash = digestmod.new(label).digest()

    # Generate zero-padding
    zpad = "\0" * (k - len(message) - 2*hLen - 2)

    # Generate the data block
    #   DB := lHash || zpad || 0x01 || message
    DB = "".join((lHash, zpad, "\x01", message))

    # Generate a random seed
    if seed is None:
        seed = randfunc(hLen)

    # Generate and apply the data mask
    #   maskedDB := DB XOR MGF(seed)
    dbMask = mgf(seed, len(DB), digestmod)
    maskedDB = strxor(DB, dbMask)

    # Generate any apply the seed mask
    #   maskedSeed := seed XOR MGF(maskedDB)
    seedMask = mgf(maskedDB, len(seed), digestmod)
    maskedSeed = strxor(seed, seedMask)

    # Return the padded message
    #   EM := 0x00 || maskedSeed || maskedDB
    EM = "".join(('\x00', maskedSeed, maskedDB))
    assert len(EM) == k
    return EM

def EME_OAEP_decode(padded_message, label, digestmod, mgf):
    """Decode a padded message from an RSA decryption.

    This performs EME-OAEP decoding according to RSA PKCS#1 v2.1.
    """

    # Find the message length
    k = len(padded_message)

    # Hash the label
    lHash = digestmod.new(label).digest()
    hLen = digestmod.digest_size

    # Split the encoded message
    #   EM = Y || maskedSeed || maskedDB
    # NB: To avoid timing attacks, we only check the validity of the message
    # after we've done all of the calculations.
    Y = padded_message[:1]
    maskedSeed = padded_message[1:1+hLen]
    maskedDB = padded_message[1+hLen:]

    # Generate and remove the seed mask
    #   seed := maskedSeed XOR MGF(maskedDB)
    seedMask = mgf(maskedDB, len(maskedSeed), digestmod)
    seed = strxor(maskedSeed, seedMask)

    # Generate and remove the data mask
    #   DB := maskedDB XOR MGF(seed)
    dbMask = mgf(seed, len(maskedDB), digestmod)
    DB = strxor(maskedDB, dbMask)

    # Split DB into its constituent parts
    #   DB = lHash || zpad || 0x01 || M
    zpad = "\0" * (k - len(message) - 2*hLen - 2)
    alleged_lHash = DB[:hLen]
    alleged_zpad = DB[hLen:hLen+len(zpad)]
    alleged_one = DB[hLen+len(zpad):hLen+len(zpad)+1]
    alleged_message = DB[hLen+len(zpad)+1:]

    # Check validity of message, taking care to behave the same every time.
    fail = (Y != '\x00')
    fail = (zpad != alleged_zpad) or fail
    fail = (alleged_lHash != lHash) or fail
    fail = (alleged_one != '\x01') or fail
    if fail:
        raise ValueError("decryption error")

    # Return the un-padded message
    return alleged_message

class RSAES_OAEP:
    """RSA Encryption Scheme using Optimal [sic] Asymmetric Encryption Padding (OAEP)

    This is the recommended primitive for doing RSA public-key encryption.
    """

    mgf = MGF1

    def __init__(self, RSAobj, mode, digestmod=None, randfunc=None):
        if mode not in (MODE_OAEP_ENCRYPT, MODE_OAEP_SIGN):
            raise ValueError("Invalid mode specified")
        self.mode = mode
        if digestmod is None:
            from Crypto.Hash import SHA256 as digestmod
        if rng is None:
            rng = Random.new()

        self._rsaobj = RSAobj
        self._digestmod = digestmod
        self._randfunc = randfunc

    def encrypt(self, message, label=""):
        # Check that the key is intended to be used for encryption
        if self.mode != MODE_OAEP_ENCRYPT:
            raise TypeError("key cannot be used for encryption.")

        # Pad the message
        k = floor_div(self._rsaobj.size(), 8)
        m = EME_OAEP_encode(k, message, label, digestmod=self._digestmod, mgf=self.mgf, rng=self._rng)

        # Perform RSA blinding (if possible)
        if self._rsaobj.can_blind():
            r = StrongRandom(self._rng).randrange(1, 1L << self._rsaobj.size())
            m = self._rsaobj.blind(m, r)

        # Encrypt the (padded) message
        (c,) = self._rsaobj.encrypt(m, "")

        # Un-blind
        if self._rsaobj.can_blind():
            c = self._rsaobj.unblind(c, r)
        return c

    def decrypt(self, ciphertext, label=""):
        # Check that the key is intended to be used for encryption
        if self.mode != MODE_OAEP_ENCRYPT or not self.key.has_private():
            raise TypeError("key cannot be used for decryption.")

        # Perform RSA blinding (if possible)
        if self._rsaobj.can_blind():
            r = StrongRandom(self._rng).randrange(1, 1L << self._rsaobj.size())
            c = self._rsaobj.blind(ciphertext, r)
        else:
            c = ciphertext

        # Decrypt the (padded) message
        m = self._rsaobj.decrypt(c)

        # Un-blind
        if self_rsaobj.can_blind():
            m = self._rsaobj.unblind(m, r)

        # Un-pad and return the message
        message = EME_OAEP_decode(m, label, digestmod=self._digestmod, mgf=self.mgf)
        return message

def generate(bits, mode, digestmod=None, randfunc=None):
    rsaObj = RSA.generate(bits, randfunc=randfunc)
    return RSAES_OAEP(rsaObj, mode, digestmod=digestmod, randfunc=randfunc)

def construct(tup, mode, digestmod=None, randfunc=None):
    rsaObj = RSA.construct(tup, randfunc=randfunc)
    return RSAES_OAEP(rsaObj, mode, digestmod=digestmod, randfunc=randfunc)

#def new(rsaobj, mode, digestmod=None, randfunc=None):
#    """Create a new PKCS#1 object"""

# vim:set ts=4 sw=4 sts=4 expandtab:
