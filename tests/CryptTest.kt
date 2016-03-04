package de.lathspell.test.kotlin.crypt

import org.junit.Assert.*
import org.junit.Test

class CryptTest {

    [Test]
    fun testDefaultCryptVariant() {
        assertTrue(Crypt().crypt("secret").startsWith("\$6\$"));
    }

    /** An empty string as salt is invalid as it could not be verified by crypt(3). */
    [Test]
    fun testEmptySalt() {
        var catched : Exception? = null
        try {
            Crypt().crypt("secret", "");
        } catch (e : Exception) {
            catched = e
        }
        assertNotNull(catched)
    }

}
