package de.lathspell.test.kotlin.crypt

import org.junit.Assert.*
import org.junit.Test

class Sha256CryptTest {

    [Test]
    fun testSha256CryptStrings() {
        // empty data
        assertEquals("\$5\$foo\$Fq9CX624QIfnCAmlGiPKLlAasdacKCRxZztPoeo7o0B", Crypt().crypt("", "\$5\$foo"));
        // salt gets cut at dollar sign
        assertEquals("\$5\$1234\$21PxqspGtPQRhVWlPHlbvBGon3Sw3hkPOn8EFKEV7E5", Crypt().crypt("secret", "\$5\$1234"));
        assertEquals("\$5\$1234\$21PxqspGtPQRhVWlPHlbvBGon3Sw3hkPOn8EFKEV7E5", Crypt().crypt("secret", "\$5\$1234\$567"));
        assertEquals("\$5\$1234\$21PxqspGtPQRhVWlPHlbvBGon3Sw3hkPOn8EFKEV7E5", Crypt().crypt("secret", "\$5\$1234\$567\$890"));
        // salt gets cut at maximum length
        assertEquals("\$5\$1234567890123456\$GUiFKBSTUAGvcK772ulTDPltkTOLtFvPOmp9o.9FNPB", Crypt().crypt("secret", "\$5\$1234567890123456"));
        assertEquals("\$5\$1234567890123456\$GUiFKBSTUAGvcK772ulTDPltkTOLtFvPOmp9o.9FNPB", Crypt().crypt("secret", "\$5\$123456789012345678"));
    }

    [Test]
    fun testSha256CryptBytes() {
        // An empty Bytearray equals an empty String
        assertEquals("\$5\$foo\$Fq9CX624QIfnCAmlGiPKLlAasdacKCRxZztPoeo7o0B", Crypt().crypt(ByteArray(0), "\$5\$foo"));
        // UTF-8 stores \u00e4 "a with diaeresis" as two bytes 0xc3 0xa4.
        assertEquals("\$5\$./\$iH66LwY5sTDTdHeOxq5nvNDVAxuoCcyH/y6Ptte82P8", Crypt().crypt("t\u00e4st", "\$5\$./\$"));
        // ISO-8859-1 stores "a with diaeresis" as single byte 0xe4.
        assertEquals("\$5\$./\$qx5gFfCzjuWUOvsDDy.5Nor3UULPIqLVBZhgGNS0c14", Crypt().crypt("t\u00e4st".getBytes("ISO-8859-1"), "\$5\$./\$"));
    }

}
