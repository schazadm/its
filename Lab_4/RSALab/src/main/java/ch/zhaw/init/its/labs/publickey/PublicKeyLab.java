package ch.zhaw.init.its.labs.publickey;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class PublicKeyLab {
    private static final String messageFilename = "message-with-signature.bin";
    private static final String keypairFilename = "keypair.rsa";

    public static void main(String[] args) throws FileNotFoundException, IOException, ClassNotFoundException, BadMessageException {
        PublicKeyLab lab = new PublicKeyLab();

//         lab.exercise1();
        lab.exercise3(args);
        // lab.exercise9GenerateSignature(args);
        // lab.exercise9VerifySignature(args);
    }

    private void exercise9GenerateSignature(String[] args) throws BadMessageException, FileNotFoundException, IOException {
        final String messageString = args[0];
        final BigInteger message = BigIntegerEncoder.encode(messageString);

        banner("Exercise 11 (signature generation)");

        generateKeypairIfNotExists();

        // --------> Your solution here! <--------
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

    private void exercise9VerifySignature(String[] args) throws BadMessageException {
        boolean ok = false;

        banner("Exercise 11 (signature verification)");

        try (ObjectInputStream key = new ObjectInputStream(new FileInputStream(keypairFilename))) {
            final RSA keypair = new RSA(key);

            // --------> Your solution here! <--------
        } catch (FileNotFoundException e) {
            System.err.println("Can't find keypair file \"" + keypairFilename + "\"");
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }

        if (ok) {
            System.out.println("Signature verified successfully");
        } else {
            System.out.println("Signature did not verify successfully");
        }
    }

    private void exercise1() {
        final int[] workFactorsBits = {128, 256, 384, 512};

        banner("Exercise 1");
        for (int wfBits : workFactorsBits) {
            int keyLength = findRSAKeyLengthForWorkFactorInBits(wfBits);
            System.out.format("%4d bits work factor: %6d bits RSA exponent\n", wfBits, keyLength);
        }
    }

    private void exercise3(String[] args) throws IOException, BadMessageException, ClassNotFoundException {
        if (args.length == 0)
            throw new IOException("Arguments empty");

        String stringMessage = args[0];
        // use string bytes to generate the BigInteger
        BigInteger message = new BigInteger(stringMessage.getBytes(StandardCharsets.US_ASCII));

        if (Files.notExists(Path.of(keypairFilename))) {
            generateKeypairIfNotExists();
        }

        try (ObjectInputStream key = new ObjectInputStream(new FileInputStream(keypairFilename))) {
            final RSA rsa = new RSA(key);
            BigInteger cipher = rsa.encrypt(message);
            ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ciphertext"));
            oos.writeObject(cipher);
            oos.close();

            ObjectInputStream ois = new ObjectInputStream(new FileInputStream("ciphertext"));
            BigInteger cipherFromFile = (BigInteger) ois.readObject();
            BigInteger messageNumber = rsa.decrypt(cipherFromFile);
            String decryptedMessage = new String(messageNumber.toByteArray(), StandardCharsets.US_ASCII);
            banner("Exercise 3:");
            System.out.printf("Cleartext: %s\nCiphertext: %s\nDecrypted Cleartext: %s%n", stringMessage, cipher, decryptedMessage);
        } catch (FileNotFoundException e) {
            System.err.println("Can't find keypair file \"" + keypairFilename + "\"");
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
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
