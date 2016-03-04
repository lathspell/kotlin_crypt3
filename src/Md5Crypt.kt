package de.lathspell.test.kotlin.crypt

import java.util.Arrays
import java.util.ArrayList
import java.util.List
import java.util.regex.Matcher
import java.util.regex.Pattern
import java.util.Random
import java.security.MessageDigest

/** MD5-based Unix crypt implementation.
*
* Based on the C implementation from Poul-Henning Kamp which was released under
* the following licence:
*  ----------------------------------------------------------------------------
* "THE BEER-WARE LICENSE" (Revision 42):
* <phk@login.dknet.dk> wrote this file.  As long as you retain this notice you
* can do whatever you want with this stuff. If we meet some day, and you think
* this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
* ----------------------------------------------------------------------------
* Source:
*   $FreeBSD: src/lib/libcrypt/crypt-md5.c,v 1.1 1999/01/21 13:50:09 brandon Exp $
*   http://www.freebsd.org/cgi/cvsweb.cgi/src/lib/libcrypt/crypt-md5.c?rev=1.1;content-type=text%2Fplain
*
* Conversion to Kotlin by Christian Hammers <ch@lathspell.de>, no rights reserved.
*
* The C style comments are from the original C code, the ones with "//" from me.
*/
class Md5Crypt() {

    /** The Identifier of this crypt() variant. */
    val MD5_SALT_PREFIX = "\$1\$"

    /** The MessageDigest MD5_ALGORITHM. */
    private val MD5_ALGORITHM = "MD5"

    /** The number of bytes of the final hash. */
    private val BLOCKSIZE = 16

    /** The number of rounds of the big loop. */
    private val ROUNDS = 1000

    private val SALT_REGEX = "^\\\$1\\\$([\\.\\/a-zA-Z0-9]{1,8}).*"

    /* Table with characters for base64 transformation.  */
    private val B64T = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

    /** Generates a libc crypt() compatible hash value using the MD5 based "$1$" mechanism. */
    fun md5Crypt(key_bytes : ByteArray, salt : String) : String {
        val key_len = key_bytes.size

        // Extract the real salt from the given string which can be a complete hash string.
        var salt_string = ""
        if (salt == null) {
            for (i in 1..8) {
                salt_string += B64T.get(Random().nextInt(B64T.length))
            }
        } else {
            val p = Pattern.compile(SALT_REGEX)
            val m = p?.matcher(salt);
            if (m == null || !m.find()) throw IllegalArgumentException("Invalid salt value: '$salt'!")
            salt_string = m.group(1) ?: throw NullPointerException()
        }
        val salt_bytes = salt_string.getBytes()
        val salt_len = salt_bytes.size

        var ctx = MessageDigest.getInstance(MD5_ALGORITHM) ?: throw NullPointerException()

        /* The password first, since that is what is most unknown */
        ctx.update(key_bytes)

        /* Then our magic string */
        ctx.update(MD5_SALT_PREFIX.toByteArray())

        /* Then the raw salt */
        ctx.update(salt_bytes)


        /* Then just as many characters of the MD5(pw,salt,pw) */
        var ctx1 = MessageDigest.getInstance(MD5_ALGORITHM) ?: throw NullPointerException()
        ctx1.update(key_bytes)
        ctx1.update(salt_bytes)
        ctx1.update(key_bytes)
        var final = ctx1.digest() ?: throw NullPointerException()
        var ii = key_len
        while (ii > 0) {
            ctx.update(final, 0, if (ii > 16) 16 else ii)
            ii -= 16
        }

        /* Don't leave anything around in vm they could use. */
        final.fill(0)

        /* Then something really weird... */
        ii = key_len
        var j = 0
        while (ii > 0) {
            if ((ii and 1) == 1) {
                ctx.update(final.get(j))
            } else {
                ctx.update(key_bytes.get(j))
            }
            ii = ii shr 1
        }

        /* Now make the output string */
        var passwd = MD5_SALT_PREFIX + salt_string + "$"
        final = ctx.digest() ?: throw NullPointerException()

        /*
        * and now, just to make sure things don't run too fast
        * On a 60 Mhz Pentium this takes 34 msec, so you would
        * need 30 seconds to build a 1000 entry dictionary...
        */
        for (i in 0..ROUNDS - 1) {
            ctx1 = MessageDigest.getInstance(MD5_ALGORITHM) ?: throw NullPointerException()
            if ((i and 1) != 0) {
                ctx1.update(key_bytes)
            } else {
                ctx1.update(final, 0, BLOCKSIZE)
            }

            if ((i mod 3) != 0) {
                ctx1.update(salt_bytes)
            }

            if ((i mod 7) != 0) {
                ctx1.update(key_bytes)
            }

            if ((i and 1) != 0) {
                ctx1.update(final, 0, BLOCKSIZE)
            } else {
                ctx1.update(key_bytes)
            }
            final = ctx1.digest() ?: throw NullPointerException()
        }

        // The following was identical to the Sha2Crypt code:
        var buflen = MD5_SALT_PREFIX.length() - 1 + salt_string.length() + 1 + BLOCKSIZE + 1

        inline fun b64from24bit(B2 : Byte, B1 : Byte, B0 : Byte, N : Int) {
            var w = (B2.toInt().shl(16).and(0x00ffffff) or B1.toInt().shl(8).and(0x00ffff) or B0.toInt().and(0xff))
            var n = N
            while (n-- > 0 && buflen > 0) {
                passwd += B64T[w and 0x3f]
                buflen--
                w = w shr 6
            }
        }

        b64from24bit(final[0], final[ 6], final[12], 4)
        b64from24bit(final[1], final[ 7], final[13], 4)
        b64from24bit(final[2], final[ 8], final[14], 4)
        b64from24bit(final[3], final[ 9], final[15], 4)
        b64from24bit(final[4], final[10], final[ 5], 4)
        b64from24bit(0, 0, final[11], 2)

        /* Don't leave anything around in vm they could use. */
        final.fill(0)

        return passwd
    }
}
