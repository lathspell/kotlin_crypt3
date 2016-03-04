# libc compatible crypt(3) implementation in Kotlin

This implementation of the libc crypt(3) function supports the following hash algorithms:
* DES based traditional Unix crypt using two characters as salt
* MD5 based crypt using salt values starting with "$1$"
* SHA-256 based crypt using salt values starting with "$5$"
* SHA-512 based crypt using salt values starting with "$6$"
 
