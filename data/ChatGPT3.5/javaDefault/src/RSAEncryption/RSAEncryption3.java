import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.*;

public class RSAEncryption3 {

    private static final String PUBLIC_KEY_FILE = "public.key";
    private static final String PRIVATE_KEY_FILE = "private.key";
    private static final String SYMMETRIC_KEY_FILE = "symmetric.key";

    public static void generateRSAKeys() throws NoSuchAlgorithmException, IOException {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        try (ObjectOutputStream publicKeyStream = new ObjectOutputStream(new FileOutputStream(PUBLIC_KEY_FILE));
             ObjectOutputStream privateKeyStream = new ObjectOutputStream(new FileOutputStream(PRIVATE_KEY_FILE))) {

            publicKeyStream.writeObject(keyPair.getPublic());
            privateKeyStream.writeObject(keyPair.getPrivate());
        }
    }

    public static void generateSymmetricKey() throws NoSuchAlgorithmException, IOException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey secretKey = keyGenerator.generateKey();

        try (ObjectOutputStream keyStream = new ObjectOutputStream(new FileOutputStream(SYMMETRIC_KEY_FILE))) {
            keyStream.writeObject(secretKey);
        }
    }

    public static void encryptSymmetricKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        try (ObjectInputStream publicKeyFileStream = new ObjectInputStream(new FileInputStream(PUBLIC_KEY_FILE));
             ObjectInputStream symmetricKeyFileStream = new ObjectInputStream(new FileInputStream(SYMMETRIC_KEY_FILE));
             ObjectOutputStream encryptedKeyStream = new ObjectOutputStream(new FileOutputStream("encrypted_symmetric.key"))) {

            PublicKey publicKey = (PublicKey) publicKeyFileStream.readObject();
            SecretKey symmetricKey = (SecretKey) symmetricKeyFileStream.readObject();

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedKey = cipher.doFinal(symmetricKey.getEncoded());

            encryptedKeyStream.writeObject(encryptedKey);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    public static void decryptSymmetricKey() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        try (ObjectInputStream privateKeyFileStream = new ObjectInputStream(new FileInputStream(PRIVATE_KEY_FILE));
             ObjectInputStream encryptedKeyFileStream = new ObjectInputStream(new FileInputStream("encrypted_symmetric.key"));
             ObjectOutputStream decryptedKeyStream = new ObjectOutputStream(new FileOutputStream("decrypted_symmetric.key"))) {

            PrivateKey privateKey = (PrivateKey) privateKeyFileStream.readObject();
            byte[] encryptedKey = (byte[]) encryptedKeyFileStream.readObject();

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedKey = cipher.doFinal(encryptedKey);

            decryptedKeyStream.writeObject(decryptedKey);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        try {
            generateRSAKeys();
            generateSymmetricKey();
            encryptSymmetricKey();
            decryptSymmetricKey();
            System.out.println("RSA encryption and decryption completed successfully.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}