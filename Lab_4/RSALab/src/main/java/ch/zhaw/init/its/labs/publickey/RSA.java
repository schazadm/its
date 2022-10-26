package ch.zhaw.init.its.labs.publickey;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OptionalDataException;
import java.math.BigInteger;

import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

public class RSA {
    /**
     * modulus
     */
    private final BigInteger n;
    /**
     * public key
     */
    private final BigInteger e;
    /**
     * private key
     */
    private BigInteger d;

    private static final int DEFAULT_MODULUS_LENGTH = 2048;
    private static final int DEFAULT_P_LENGTH = DEFAULT_MODULUS_LENGTH / 2 - 9;
    private static final int DEFAULT_Q_LENGTH = DEFAULT_MODULUS_LENGTH / 2 + 9;

    private static final BigInteger PUBLIC_EXPONENT = BigInteger.valueOf(65537);

    /**
     * Generates a random RSA key pair.
     * <p>
     * This constructor generates a random RSA key pair of unknown, but substantial,
     * modulus length. The public exponent is 65537.
     * https://www.geeksforgeeks.org/java-program-to-implement-the-rsa-algorithm/
     */
    public RSA() {
        // FIXME: try again and run tests
        BigInteger p = BigInteger.probablePrime(DEFAULT_P_LENGTH, new Random());
        BigInteger q = BigInteger.probablePrime(DEFAULT_Q_LENGTH, new Random());

        BigInteger p_sub_1 = p.subtract(BigInteger.ONE); // (p - 1)
        BigInteger q_sub_1 = q.subtract(BigInteger.ONE); // (q - 1)
        BigInteger z = p_sub_1.multiply(q_sub_1); // (p - 1) * (q - 1)

        n = p.multiply(q);
        e = PUBLIC_EXPONENT;

        int i = 0;
        BigInteger tmp;
        BigInteger x;

        do {
            tmp = z.multiply(BigInteger.valueOf(i)); // z * i
            x = tmp.add(BigInteger.ONE); // 1 + (z * i)
            i++;
        } while (x.mod(e).equals(BigInteger.ZERO));

        // d is for private key exponent
        d = x.divide(e);
    }

    /**
     * Reads a public key or a key pair from input stream.
     *
     * @param is the input stream to read the public key or key pair from
     * @throws IOException if either the modulus, public exponent, or private
     *                     exponent can not be read
     */
    public RSA(ObjectInputStream is) throws IOException, ClassNotFoundException {
        n = (BigInteger) is.readObject();
        e = (BigInteger) is.readObject();

        try {
            d = (BigInteger) is.readObject();
        } catch (OptionalDataException e) {
            if (!e.eof) {
                throw e;
            }
        }
    }

    /**
     * Encrypts the plain text with the public key.
     *
     * @param plain the plain text to encrypt
     * @return the ciphertext
     * @throws BadMessageException then the plain text is too large or too small
     */
    public BigInteger encrypt(BigInteger plain) throws BadMessageException {
        if (plain.compareTo(n) > 0) {
            throw new BadMessageException("plaintext too large");
        }

        if (plain.compareTo(BigInteger.ZERO) <= 0) {
            throw new BadMessageException("plaintext too small");
        }

        return plain.modPow(e, n);
    }

    /**
     * Decrypts the ciphertext with the private key.
     *
     * @param cipher the ciphertext to decrypt
     * @return plaintext
     */
    public BigInteger decrypt(BigInteger cipher) throws BadMessageException {
        if (d == null) {
            throw new BadMessageException("don't have private key");
        }

        if (cipher.compareTo(n) > 0) {
            throw new BadMessageException("ciphertext too large");
        }

        if (cipher.compareTo(BigInteger.ZERO) <= 0) {
            throw new BadMessageException("ciphertext too small");
        }

        return cipher.modPow(d, n);
    }

    /**
     * Saves the entire key pair.
     *
     * @param os the output stream to which to save the key pair
     * @throws IOException if saving goes wrong or there is no private key to save
     */
    public void save(ObjectOutputStream os) throws IOException {
        savePublic(os);

        if (d != null) {
            os.writeObject(d);
        } else {
            throw new IOException("don't have private key to save");
        }
    }

    /**
     * Saves only the public part of the key pair.
     *
     * @param os the output stream to which to save the public key
     * @throws IOException if saving goes wrong
     */
    public void savePublic(ObjectOutputStream os) throws IOException {
        os.writeObject(n);
        os.writeObject(e);
    }

    /**
     * Signs a message with the private key.
     *
     * @param message the message to sign
     * @return the signature for this message
     * @throws BadMessageException if something is wrong with this message or there is no private key
     */
    public BigInteger sign(BigInteger message) throws BadMessageException {
        if (d == null) throw new BadMessageException("Private Key is N/A");
        return decrypt(message);
    }

    /**
     * Verifies a signature of a message.
     *
     * @param message   the message whose signature to check
     * @param signature the signature to check
     * @return true iff the signature was made for this message by this key
     * @throws BadMessageException if something is wrong with this message
     */
    public boolean verify(BigInteger message, BigInteger signature) throws BadMessageException {
        return encrypt(signature).equals(message);
    }

    public boolean equals(RSA other) {
        return this.n.equals(other.n)
                && this.e.equals(other.e)
                && (this.d == null && other.d == null || this.d.equals(other.d));
    }
}
