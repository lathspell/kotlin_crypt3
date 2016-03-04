package de.lathspell.test.kotlin.crypt

import org.junit.Assert.*
import org.junit.Test

public class EglibcCryptTest {

    /**
    * Test cases from eglibc.
    */
    [Test]
    fun testSha512CryptLibc() {
        val tests = array<Array<String>>(
        array("\$6\$saltstring", "Hello world!",
        "\$6\$saltstring\$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJu"
        + "esI68u4OTLiBFdcbYEdFCoEOfaS35inz1"),
        array("\$6\$rounds=10000\$saltstringsaltstring", "Hello world!",
        "\$6\$rounds=10000\$saltstringsaltst\$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sb"
        + "HbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v."),
        array("\$6\$rounds=5000\$toolongsaltstring", "This is just a test",
        "\$6\$rounds=5000\$toolongsaltstrin\$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQ"
        + "zQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0"),
        array("\$6\$rounds=1400\$anotherlongsaltstring",
        "a very much longer text to encrypt.  This one even stretches over more"
        + "than one line.",
        "\$6\$rounds=1400\$anotherlongsalts\$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wP"
        + "vMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1"),
        array("\$6\$rounds=77777\$short",
        "we have a short salt string but not a short password",
        "\$6\$rounds=77777\$short\$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0g"
        + "ge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0"),
        array("\$6\$rounds=123456\$asaltof16chars..", "a short string",
        "\$6\$rounds=123456\$asaltof16chars..\$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwc"
        + "elCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1"),
        array("\$6\$rounds=10\$roundstoolow", "the minimum number is still observed",
        "\$6\$rounds=1000\$roundstoolow\$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1x"
        + "hLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX."));
        for (test in tests) {
            assertEquals(test[2],Crypt().crypt(test[1], test[0]));
        }
    }


    /**
    * Test cases from eglibc sha512, ported to sha256.
    */
    [Test]
    fun testSha256CryptLibcLike() {
        val tests = array<Array<String>>(
        array("\$5\$saltstring", "Hello world!", "\$5\$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5"),
        array("\$5\$rounds=10000\$saltstringsaltstring", "Hello world!", "\$5\$rounds=10000\$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA"),
        array("\$5\$rounds=5000\$toolongsaltstring", "This is just a test", "\$5\$rounds=5000\$toolongsaltstrin\$Un/5jzAHMgOGZ5.mWJpuVolil07guHPvOW8mGRcvxa5"),
        array("\$5\$rounds=1400\$anotherlongsaltstring", "a very much longer text to encrypt.  This one even stretches over morethan one line.", "\$5\$rounds=1400\$anotherlongsalts\$Rx.j8H.h8HjEDGomFU8bDkXm3XIUnzyxf12oP84Bnq1"),
        array("\$5\$rounds=77777\$short", "we have a short salt string but not a short password", "\$5\$rounds=77777\$short\$JiO1O3ZpDAxGJeaDIuqCoEFysAe1mZNJRs3pw0KQRd/"),
        array("\$5\$rounds=123456\$asaltof16chars..", "a short string", "\$5\$rounds=123456\$asaltof16chars..\$gP3VQ/6X7UUEW3HkBn2w1/Ptq2jxPyzV/cZKmF/wJvD"),
        array("\$5\$rounds=10\$roundstoolow", "the minimum number is still observed", "\$5\$rounds=1000\$roundstoolow\$yfvwcWrQ8l/K0DAWyuPMDNHpIVlTQebY9l/gL972bIC")
        )
        for (test in tests) {
            assertEquals(test[2], Crypt().crypt(test[1], test[0]));
        }
    }
}
