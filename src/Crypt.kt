package de.lathspell.test.kotlin.crypt

/** Libc compatible crypt() implementation.
 *
 * This implementation of the libc crypt(3) function supports the following
 * hash algorithms:
 * <ul>
 *   <li>DES based traditional Unix crypt using two characters as salt
 *   <li>MD5 based crypt using salt values starting with "$1$"
 *   <li>SHA-256 based crypt using salt values starting with "$5$"
 *   <li>SHA-512 based crypt using salt values starting with "$6$"
 * </ul>
 *
 */
class Crypt {

    /** Libc compatible crypt() method. */
    fun crypt(key : String, salt : String? = null) : String {
        return crypt(key.getBytes(), salt)
    }

    /** Libc compatible crypt() method. */
    fun crypt(key_bytes : ByteArray, salt : String? = null) : String {
        if (salt == null || salt.startsWith(Sha2Crypt().SHA512_PREFIX) || salt.startsWith(Sha2Crypt().SHA256_PREFIX)) {
            return Sha2Crypt().sha2Crypt(key_bytes, salt)
        } else if (salt.startsWith(Md5Crypt().MD5_SALT_PREFIX)) {
            return Md5Crypt().md5Crypt(key_bytes, salt)
        } else {
            // return UnixCrypt().unixCrypt(key_bytes, salt)
            throw Exception()
        }
    }
}
