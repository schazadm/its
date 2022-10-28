package ch.zhaw.init.its.labs.publickey;

import javax.naming.OperationNotSupportedException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Random;

public class PublicKeyLab {
    private static final String messageFilename = "message-with-signature.bin";
    private static final String messageFilenameDiff = "message-with-signature_diff.bin";
    private static final String keypairFilename = "keypair.rsa";

    public static void main(String[] args) throws IOException, BadMessageException {
        PublicKeyLab lab = new PublicKeyLab();
        // lab.exercise1();
        // lab.exercise3(args);
        // lab.exercise9GenerateSignature(args);
        lab.exercise9VerifySignature(args);
        // lab.exercise11();
    }

    private void exercise1() {
        final int[] workFactorsBits = {128, 256, 384, 512};
        banner("Exercise 1");
        for (int wfBits : workFactorsBits) {
            int keyLength = findRSAKeyLengthForWorkFactorInBits(wfBits);
            System.out.printf("%d bits work factor: %d bits RSA exponent%n", wfBits, keyLength);
        }
    }

    private void exercise3(String[] args) throws IOException {
        if (args.length == 0) throw new IOException("Arguments empty");

        String stringMessage = args[0];
        // use string bytes to generate the BigInteger
        BigInteger message = new BigInteger(stringMessage.getBytes(StandardCharsets.UTF_8));
        generateKeypairIfNotExists();

        try (ObjectInputStream key = new ObjectInputStream(new FileInputStream(keypairFilename))) {
            final RSA rsa = new RSA(key);
            BigInteger cipher = rsa.encrypt(message);
            ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ciphertext"));
            oos.writeObject(cipher);
            oos.close();

            ObjectInputStream ois = new ObjectInputStream(new FileInputStream("ciphertext"));
            BigInteger cipherFromFile = (BigInteger) ois.readObject();
            BigInteger messageNumber = rsa.decrypt(cipherFromFile);
            String decryptedMessage = new String(messageNumber.toByteArray(), StandardCharsets.UTF_8);

            banner("Exercise 3:");
            String parsedStr = cipher.toString().replaceAll("(.{50})", "$1\n");
            System.out.printf("Cleartext: %s%n", stringMessage);
            System.out.printf("Ciphertext:%n" + parsedStr + "%n");
            System.out.printf("Decrypted Cleartext: %s%n", decryptedMessage);
        } catch (FileNotFoundException e) {
            System.err.println("Can't find keypair file \"" + keypairFilename + "\"");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void exercise9GenerateSignature(String[] args) throws BadMessageException, FileNotFoundException, IOException {
        if (args.length == 0) throw new IOException("Arguments empty");

        final String messageString = args[0];
        final BigInteger encodedMessage = BigIntegerEncoder.encode(messageString);
        generateKeypairIfNotExists();

        banner("Exercise 9 (signature generation)");

        try {
            RSA rsa = new RSA(new ObjectInputStream(new FileInputStream(keypairFilename)));
            BigInteger signature = rsa.sign(encodedMessage);
            ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(messageFilename));
            oos.writeObject(encodedMessage);
            oos.writeObject(signature);
            oos.close();

            String parsedS = signature.toString().replaceAll("(.{50})", "$1\n");
            String parsedM = encodedMessage.toString().replaceAll("(.{50})", "$1\n");
            System.out.printf("Signature: %n%s%n", parsedS);
            System.out.printf("Ciphertext: %s%n", parsedM);
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (OperationNotSupportedException e) {
            System.err.println(e.getMessage());
        }
    }

    private void exercise9VerifySignature(String[] args) throws BadMessageException {
        boolean ok = false;
        banner("Exercise 9 (signature verification)");

        try (ObjectInputStream key = new ObjectInputStream(new FileInputStream(keypairFilename))) {
            final RSA keypair = new RSA(key);
            // ObjectInputStream ois = new ObjectInputStream(new FileInputStream(messageFilename));
            // Exercise 10 -> if signature is different
            ObjectInputStream ois = new ObjectInputStream(new FileInputStream(messageFilenameDiff));
            BigInteger message = (BigInteger) ois.readObject();
            BigInteger signature = (BigInteger) ois.readObject();
            ok = keypair.verify(message, signature);

            String parsedS = signature.toString().replaceAll("(.{50})", "$1\n");
            String parsedM = message.toString().replaceAll("(.{50})", "$1\n");
            System.out.printf("Signature: %n%s%n", parsedS);
            System.out.printf("Ciphertext: %s%n", parsedM);
        } catch (FileNotFoundException e) {
            System.err.println("Can't find keypair file \"" + keypairFilename + "\"");
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        } catch (OperationNotSupportedException e) {
            System.err.println(e.getMessage());
        }

        if (ok) {
            System.out.println("Signature verified successfully");
        } else {
            System.out.println("Signature did not verify successfully");
        }
    }

    /**
     * (2**m)**3 < 2**1024
     * 2**(m*3) < 2**1024
     * m*3 < 1024
     * m < 1024 / 3
     */
    private void exercise11() {
        banner("Exercise 11");
        final int[] n_bits = {1024, 2048, 3072, 4096};
        for (int bits : n_bits) {
            System.out.printf("n: %d [bit] ---> max. m len: %d [bit]%n", bits, bits / 3);
        }
    }

    private void generateKeypairIfNotExists() throws FileNotFoundException, IOException {
        // Generate keypair if none exists
        File f = new File(keypairFilename);
        if (!f.canRead()) {
            try (ObjectOutputStream os = new ObjectOutputStream(new FileOutputStream(f))) {
                RSA rsa = new RSA();
                rsa.save(os);
            }
        }
    }

    private void banner(String string) {
        System.out.println();
        System.out.println(string);
        for (int i = 0; i < string.length(); i++) {
            System.out.print('=');
        }
        System.out.println();
        System.out.println();
    }

    private int findRSAKeyLengthForWorkFactorInBits(int wfBits) {
        final double ln2 = Math.log(2.0);
        int b = 1;
        do {
            b++;
        } while ((Math.log(Math.exp(logW(b))) / ln2) < wfBits);

        return b;
    }

    private double logW(int b) {
        return 1.92 * Math.pow(b, 1.0 / 3.0) * Math.pow(Math.log(b), 2.0 / 3.0);
    }
}
