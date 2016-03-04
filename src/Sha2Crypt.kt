package de.lathspell.test.kotlin.crypt

import java.util.Arrays
import java.util.ArrayList
import java.util.List
import java.util.regex.Matcher
import java.util.regex.Pattern
import java.util.Random
import java.security.MessageDigest

/** SHA2-based Unix crypt implementation.
*
* Based on the C implementation released into the Public Domain by
* Ulrich Drepper <drepper@redhat.com>.
* http://www.akkadia.org/drepper/SHA-crypt.txt
*
* Conversion to Kotlin by Christian Hammers <ch@lathspell.de> and
* likewise put into the Public Domain.
* The numbered comments are from the algorithm description, the short
* C style ones from the original C code and the ones with "Remark" from me.
*
*/
class Sha2Crypt() {

    /** The prefixes that can be used to identify this crypt() variant. */
    val SHA256_PREFIX = "$5$"
    val SHA512_PREFIX = "$6$"

    /* Prefix for optional rounds specification.  */
    private val ROUNDS_PREFIX = "rounds="

    /* Default number of rounds if not explicitly specified.  */
    private val ROUNDS_DEFAULT = 5000

    /* Minimum number of rounds.  */
    private val ROUNDS_MIN = 1000

    /* Maximum number of rounds.  */
    private val ROUNDS_MAX = 999999999

    private val SHA2_REGEX = "^\\\$([56])\\\$(rounds=(\\d+)\\$)?([\\.\\/a-zA-Z0-9]{1,16}).*"

    /* Table with characters for base64 transformation.  */
    private val B64T = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

    /** The number of bytes the final hash value will have. */
    private val SHA256_BLOCKSIZE = 32
    private val SHA512_BLOCKSIZE = 64

    /** The MessageDigest algorithm. */
    private val SHA256_ALGORITHM = "SHA-256"
    private val SHA512_ALGORITHM = "SHA-512"

    /** Generates Libc crypt() compatible hash values in either the '$5$' or '$6$' variant. */
    fun sha2Crypt(key_bytes : ByteArray, salt : String?) : String {
        // Extract the real salt from the given string which can be a complete hash string.
        var salt_string = ""
        var rounds = ROUNDS_DEFAULT
        var rounds_custom = false
        var is5 = false
        if (salt == null) {
            for (i in 1..8) {
                salt_string += B64T.get(Random().nextInt(B64T.length))
            }
        } else {
            val p = Pattern.compile(SHA2_REGEX)
            val m = p?.matcher(salt);
            if (m == null || !m.find()) throw IllegalArgumentException("Invalid salt value: '$salt'!")
            if (m.group(1).equals("5")) {
                is5 = true
            }
            if (m.group(3) != null) {
                rounds = Integer.valueOf(m.group(3)) ?: throw NullPointerException()
                rounds = Math.max(ROUNDS_MIN, Math.min(ROUNDS_MAX, rounds))
                rounds_custom = true
            }
            salt_string = m.group(4) ?: throw NullPointerException()
        }
        val blocksize = if (is5) SHA256_BLOCKSIZE else SHA512_BLOCKSIZE
        val algorithm = if (is5) SHA256_ALGORITHM else SHA512_ALGORITHM
        val salt_prefix = if (is5) SHA256_PREFIX else SHA512_PREFIX
        val salt_bytes = salt_string.getBytes()
        val salt_len = salt_bytes.size
        val key_len = key_bytes.size

        // 1.  start digest A
        // Prepare for the real work.
        var ctx = MessageDigest.getInstance(algorithm) ?: throw NullPointerException()

        // 2.  the password string is added to digest A
        /* Add the key string. */
        ctx.update(key_bytes)

        // 3.  the salt string is added to digest A.  This is just the salt string
        // itself without the enclosing '$', without the magic prefix $5$ and
        // $6$ respectively and without the rounds=<N> specification.
        //
        // NB: the MD5 algorithm did add the $1$ prefix.  This is not deemed
        // necessary since it is a constant string and does not add security
        // and /possibly/ allows a plain text attack.  Since the rounds=<N>
        // specification should never be added this would also create an
        // inconsistency.
        /* The last part is the salt string.  This must be at most 16 characters and it ends at the
         * first `$' character (for compatibility with existing implementations). */
        ctx.update(salt_bytes)

        // 4.  start digest B
        /* Compute alternate sha512 sum with input KEY, SALT, and KEY.
         * The final result will be added to the first context. */
        var alt_ctx = MessageDigest.getInstance(algorithm) ?: throw NullPointerException()

        // 5.  add the password to digest B
        /* Add key. */
        alt_ctx.update(key_bytes)

        // 6.  add the salt string to digest B
        /* Add salt. */
        alt_ctx.update(salt_bytes)

        // 7.  add the password again to digest B
        /* Add key again. */
        alt_ctx.update(key_bytes)

        // 8.  finish digest B
        /* Now get result of this (32 bytes) and add it to the other context. */
        var alt_result = alt_ctx.digest() ?: throw NullPointerException()

        // 9.  For each block of 32 or 64 bytes in the password string (excluding
        // the terminating NUL in the C representation), add digest B to digest A
        /* Add for any character in the key one byte of the alternate sum. */
        /* (Remark: the C code comment seems wrong for key length > 32!) */
        var cnt = key_bytes.size
        while (cnt > blocksize) {
            ctx.update(alt_result, 0, blocksize)
            cnt -= blocksize
        }

        // 10. For the remaining N bytes of the password string add the first
        // N bytes of digest B to digest A
        ctx.update(alt_result, 0, cnt)

        // 11. For each bit of the binary representation of the length of the
        // password string up to and including the highest 1-digit, starting
        // from to lowest bit position (numeric value 1):
        //
        // a) for a 1-digit add digest B to digest A
        //
        // b) for a 0-digit add the password string
        //
        // NB: this step differs significantly from the MD5 algorithm.  It
        // adds more randomness.
        /* Take the binary representation of the length of the key and for every
         * 1 add the alternate sum, for every 0 the key. */
        cnt = key_bytes.size
        while (cnt > 0) {
            if ((cnt and 1) != 0) {
                ctx.update(alt_result, 0, blocksize)
            } else {
                ctx.update(key_bytes)
            }
            cnt = cnt shr 1
        }

        // 12. finish digest A
        /* Create intermediate result. */
        alt_result = ctx.digest() ?: throw NullPointerException()

        // 13. start digest DP
        /* Start computation of P byte sequence. */
        alt_ctx = MessageDigest.getInstance(algorithm) ?: throw NullPointerException()

        // 14. for every byte in the password (excluding the terminating NUL byte
        // in the C representation of the string)
        //
        //   add the password to digest DP
        /* For every character in the password add the entire password. */
        for (i in 1..key_len) {
            alt_ctx.update(key_bytes)
        }

        // 15. finish digest DP
        /* Finish the digest. */
        var temp_result = alt_ctx.digest() ?: throw NullPointerException()

        // 16. produce byte sequence P of the same length as the password where
        //
        //     a) for each block of 32 or 64 bytes of length of the password string
        //        the entire digest DP is used
        //
        //     b) for the remaining N (up to  31 or 63) bytes use the first N
        //        bytes of digest DP
        /* Create byte sequence P. */
        val p_bytes = ByteArray(key_len)
        var cp = 0
        while (cp < key_len - blocksize) {
            System.arraycopy(temp_result, 0, p_bytes, cp, blocksize);
            cp += blocksize
        }
        System.arraycopy(temp_result, 0, p_bytes, cp, key_len - cp);

        // 17. start digest DS
        /* Start computation of S byte sequence. */
        alt_ctx = MessageDigest.getInstance(algorithm) ?: throw NullPointerException()

        // 18. repeast the following 16+A[0] times, where A[0] represents the first
        //     byte in digest A interpreted as an 8-bit unsigned value
        //
        //       add the salt to digest DS
        /* For every character in the password add the entire password. */
        for (i in 1..(16 + (alt_result.get(0).toInt() and 0xff))) {
            alt_ctx.update(salt_bytes)
        }

        // 19. finish digest DS
        /* Finish the digest. */
        temp_result = alt_ctx.digest() ?: throw NullPointerException()

        // 20. produce byte sequence S of the same length as the salt string where
        //
        //     a) for each block of 32 or 64 bytes of length of the salt string
        //        the entire digest DS is used
        //
        //     b) for the remaining N (up to  31 or 63) bytes use the first N
        //        bytes of digest DS
        /* Create byte sequence S. */
        // Remark: The salt is limited to 16 chars, how does this make sense?
        val s_bytes = ByteArray(salt_len)
        cp = 0
        while (cp < salt_len - blocksize) {
            System.arraycopy(temp_result, 0, s_bytes, cp, blocksize);
            cp += blocksize
        }
        System.arraycopy(temp_result, 0, s_bytes, cp, salt_len - cp);

        // 21. repeat a loop according to the number specified in the rounds=<N>
        //     specification in the salt (or the default value if none is
        //     present).  Each round is numbered, starting with 0 and up to N-1.
        //
        //     The loop uses a digest as input.  In the first round it is the
        //     digest produced in step 12.  In the latter steps it is the digest
        //     produced in step 21.h.  The following text uses the notation
        //     "digest A/C" to desribe this behavior.
        /* Repeatedly run the collected hash value through sha512 to burn CPU cycles. */
        for (i in 0..rounds - 1) {
            // a) start digest C
            /* New context. */
            ctx = MessageDigest.getInstance(algorithm) ?: throw NullPointerException()

            // b) for odd round numbers add the byte sequense P to digest C
            // c) for even round numbers add digest A/C
            /* Add key or last result. */
            if ((i and 1) != 0) {
                ctx.update(p_bytes, 0, key_len)
            } else {
                ctx.update(alt_result, 0, blocksize)
            }

            // d) for all round numbers not divisible by 3 add the byte sequence S
            /* Add salt for numbers not divisible by 3. */
            if (i mod 3 != 0) {
                ctx.update(s_bytes, 0, salt_len)
            }

            // e) for all round numbers not divisible by 7 add the byte sequence P
            /* Add key for numbers not divisible by 7. */
            if (i mod 7 != 0) {
                ctx.update(p_bytes, 0, key_len)
            }

            // f) for odd round numbers add digest A/C
            // g) for even round numbers add the byte sequence P
            /* Add key or last result. */
            if ((i and 1) != 0) {
                ctx.update(alt_result, 0, blocksize)
            } else {
                ctx.update(p_bytes, 0, key_len)
            }

            // h) finish digest C.
            /* Create intermediate result. */
            alt_result = ctx.digest() ?: throw NullPointerException()
        }

        // 22. Produce the output string.  This is an ASCII string of the maximum
        //     size specified above, consisting of multiple pieces:
        //
        //     a) the salt prefix, $5$ or $6$ respectively
        //
        //     b) the rounds=<N> specification, if one was present in the input
        //        salt string.  A trailing '$' is added in this case to separate
        //        the rounds specification from the following text.
        //
        //     c) the salt string truncated to 16 characters
        //
        //     d) a '$' character
        /* Now we can construct the result string. It consists of three parts. */
        var buffer = salt_prefix + (if (rounds_custom) ROUNDS_PREFIX + rounds + "$" else "") + salt_string + "$"

        // e) the base-64 encoded final C digest.  The encoding used is as
        //    follows:
        // [...]
        //
        //    Each group of three bytes from the digest produces four
        //    characters as output:
        //
        //    1. character: the six low bits of the first byte
        //    2. character: the two high bits of the first byte and the
        //       four low bytes from the second byte
        //    3. character: the four high bytes from the second byte and
        //       the two low bits from the third byte
        //    4. character: the six high bits from the third byte
        //
        // The groups of three bytes are as follows (in this sequence).
        // These are the indices into the byte array containing the
        // digest, starting with index 0.  For the last group there are
        // not enough bytes left in the digest and the value zero is used
        // in its place.  This group also produces only three or two
        // characters as output for SHA-512 and SHA-512 respectively.
        var buflen = salt_prefix.length() - 1 + ROUNDS_PREFIX.length() + 9 + 1 + salt_string.length() + 1 + 86 + 1

        fun b64from24bit(B2 : Byte, B1 : Byte, B0 : Byte, N : Int) {
            var w = (B2.toInt().shl(16).and(0x00ffffff) or B1.toInt().shl(8).and(0x00ffff) or B0.toInt().and(0xff))
            var n = N
            while (n-- > 0 && buflen > 0) {
                buffer += B64T[w and 0x3f]
                buflen--
                w = w shr 6
            }
        }

        if (blocksize == 32) {
            b64from24bit(alt_result[0], alt_result[10], alt_result[20], 4);
            b64from24bit(alt_result[21], alt_result[1], alt_result[11], 4);
            b64from24bit(alt_result[12], alt_result[22], alt_result[2], 4);
            b64from24bit(alt_result[3], alt_result[13], alt_result[23], 4);
            b64from24bit(alt_result[24], alt_result[4], alt_result[14], 4);
            b64from24bit(alt_result[15], alt_result[25], alt_result[5], 4);
            b64from24bit(alt_result[6], alt_result[16], alt_result[26], 4);
            b64from24bit(alt_result[27], alt_result[7], alt_result[17], 4);
            b64from24bit(alt_result[18], alt_result[28], alt_result[8], 4);
            b64from24bit(alt_result[9], alt_result[19], alt_result[29], 4);
            b64from24bit(0, alt_result[31], alt_result[30], 3);
        } else {
            b64from24bit(alt_result[0], alt_result[21], alt_result[42], 4)
            b64from24bit(alt_result[22], alt_result[43], alt_result[1], 4)
            b64from24bit(alt_result[44], alt_result[2], alt_result[23], 4)
            b64from24bit(alt_result[3], alt_result[24], alt_result[45], 4)
            b64from24bit(alt_result[25], alt_result[46], alt_result[4], 4)
            b64from24bit(alt_result[47], alt_result[5], alt_result[26], 4)
            b64from24bit(alt_result[6], alt_result[27], alt_result[48], 4)
            b64from24bit(alt_result[28], alt_result[49], alt_result[7], 4)
            b64from24bit(alt_result[50], alt_result[8], alt_result[29], 4)
            b64from24bit(alt_result[9], alt_result[30], alt_result[51], 4)
            b64from24bit(alt_result[31], alt_result[52], alt_result[10], 4)
            b64from24bit(alt_result[53], alt_result[11], alt_result[32], 4)
            b64from24bit(alt_result[12], alt_result[33], alt_result[54], 4)
            b64from24bit(alt_result[34], alt_result[55], alt_result[13], 4)
            b64from24bit(alt_result[56], alt_result[14], alt_result[35], 4)
            b64from24bit(alt_result[15], alt_result[36], alt_result[57], 4)
            b64from24bit(alt_result[37], alt_result[58], alt_result[16], 4)
            b64from24bit(alt_result[59], alt_result[17], alt_result[38], 4)
            b64from24bit(alt_result[18], alt_result[39], alt_result[60], 4)
            b64from24bit(alt_result[40], alt_result[61], alt_result[19], 4)
            b64from24bit(alt_result[62], alt_result[20], alt_result[41], 4)
            b64from24bit(0, 0, alt_result[63], 2)
        }

        /* Clear the buffer for the intermediate result so that people attaching
         * to processes or reading core dumps cannot get any information. */
        temp_result.fill(0)
        p_bytes.fill(0)
        s_bytes.fill(0)
        ctx.reset()
        alt_ctx.reset()
        key_bytes.fill(0)
        salt_bytes.fill(0)

        return buffer
    }
}
