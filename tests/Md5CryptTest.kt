package de.lathspell.test.kotlin.crypt

import org.junit.Assert.*
import org.junit.Test

class Md5CryptTest {

    [Test]
    fun testMd5CryptStrings() {
        // empty data
        assertEquals("\$1\$foo\$9mS5ExwgIECGE5YKlD5o91", Crypt().crypt("", "\$1\$foo"));
        // salt gets cut at dollar sign
        assertEquals("\$1\$1234\$ImZYBLmYC.rbBKg9ERxX70", Crypt().crypt("secret", "\$1\$1234"));
        assertEquals("\$1\$1234\$ImZYBLmYC.rbBKg9ERxX70", Crypt().crypt("secret", "\$1\$1234\$567"));
        assertEquals("\$1\$1234\$ImZYBLmYC.rbBKg9ERxX70", Crypt().crypt("secret", "\$1\$1234\$567\$890"));
        // salt gets cut at maximum length
        assertEquals("\$1\$12345678\$hj0uLpdidjPhbMMZeno8X/", Crypt().crypt("secret", "\$1\$1234567890123456"));
        assertEquals("\$1\$12345678\$hj0uLpdidjPhbMMZeno8X/", Crypt().crypt("secret", "\$1\$123456789012345678"));
    }

    [Test]
    fun testMd5CryptBytes() {
        // An empty Bytearray equals an empty String
        assertEquals("\$1\$foo\$9mS5ExwgIECGE5YKlD5o91", Crypt().crypt(ByteArray(0), "\$1\$foo"));
        // UTF-8 stores \u00e4 "a with diaeresis" as two bytes 0xc3 0xa4.
        assertEquals("\$1\$./\$52agTEQZs877L9jyJnCNZ1", Crypt().crypt("t\u00e4st", "\$1\$./\$"));
        // ISO-8859-1 stores "a with diaeresis" as single byte 0xe4.
        assertEquals("\$1\$./\$J2UbKzGe0Cpe63WZAt6p//", Crypt().crypt("t\u00e4st".getBytes("ISO-8859-1"), "\$1\$./\$"));
    }

}
