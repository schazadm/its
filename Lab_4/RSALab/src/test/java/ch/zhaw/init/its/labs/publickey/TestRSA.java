package ch.zhaw.init.its.labs.publickey;

import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;

import org.junit.jupiter.api.Test;

class TestRSA {

    @Test
    void testGeneration() {
        try {
            for (int i = 0; i < 100; i++) {
                RSA rsa = new RSA();
            }
        } catch (Exception e) {
            fail("Urgs");
        }
    }

    @Test
    void testEncryptDecrypt() throws BadMessageException {
        try {
            RSA rsa = new RSA();
            BigInteger message = BigInteger.ONE;

            for (int i = 0; i < 100; i++) {
                BigInteger cipher = rsa.encrypt(message);
                BigInteger decrypted = rsa.decrypt(cipher);

                if (!decrypted.equals(message)) {
                    fail("Urgs");
                }

                message = message.add(BigInteger.ONE);
            }
        } catch (Exception e) {
            fail("Urgs");
        }
    }

    @Test
    void testSignVerify() throws BadMessageException {
        try {
            RSA rsa = new RSA();
            BigInteger message = BigInteger.ONE;

            for (int i = 0; i < 100; i++) {
                BigInteger signature = rsa.sign(message);

                if (!rsa.verify(message, signature)) {
                    fail("Urgs");
                }

                message = message.add(BigInteger.ONE);
            }
        } catch (Exception e) {
            fail("Urgs");
        }
    }

    @Test
    void testSerialize() throws IOException, ClassNotFoundException {
        try {
            for (int i = 0; i < 100; i++) {
                RSA rsa = new RSA();

                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                ObjectOutputStream os = new ObjectOutputStream(bos);
                rsa.save(os);

                ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
                ObjectInputStream is = new ObjectInputStream(bis);

                RSA rsaNew = new RSA(is);

                if (!rsa.equals(rsaNew)) {
                    fail("Urgs");
                }
            }
        } catch (Exception e) {
            fail("Urgs");
        }
    }
}
