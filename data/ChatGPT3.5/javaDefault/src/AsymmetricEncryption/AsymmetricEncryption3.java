import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

public class AsymmetricEncryption3 {

    private static final String ASYMMETRIC_ALGORITHM = "RSA";
    private static final String SYMMETRIC_ALGORITHM = "AES";
    private static final int KEY_SIZE = 2048;

    public static void generateKeyPair(String publicKeyFile, String privateKeyFile) {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ASYMMETRIC_ALGORITHM);
            keyGen.initialize(KEY_SIZE);
            KeyPair keyPair = keyGen.generateKeyPair();

            ObjectOutputStream publicKeyOS = new ObjectOutputStream(new FileOutputStream(publicKeyFile));
            publicKeyOS.writeObject(keyPair.getPublic());
            publicKeyOS.close();

            ObjectOutputStream privateKeyOS = new ObjectOutputStream(new FileOutputStream(privateKeyFile));
            privateKeyOS.writeObject(keyPair.getPrivate());
            privateKeyOS.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static Key generateSymmetricKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(SYMMETRIC_ALGORITHM);
            keyGen.init(256);
            return keyGen.generateKey();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void encryptSymmetricKey(String publicKeyFile, Key symmetricKey, String encryptedKeyFile) {
        try {
            ObjectInputStream publicKeyIS = new ObjectInputStream(new FileInputStream(publicKeyFile));
            Key publicKey = (Key) publicKeyIS.readObject();
            publicKeyIS.close();

            Cipher cipher = Cipher.getInstance(ASYMMETRIC_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedKey = cipher.doFinal(symmetricKey.getEncoded());

            FileOutputStream fos = new FileOutputStream(encryptedKeyFile);
            fos.write(encryptedKey);
            fos.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static Key decryptSymmetricKey(String privateKeyFile, String encryptedKeyFile) {
        try {
            ObjectInputStream privateKeyIS = new ObjectInputStream(new FileInputStream(privateKeyFile));
            Key privateKey = (Key) privateKeyIS.readObject();
            privateKeyIS.close();

            Cipher cipher = Cipher.getInstance(ASYMMETRIC_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            FileInputStream fis = new FileInputStream(encryptedKeyFile);
            byte[] encryptedKey = new byte[fis.available()];
            fis.read(encryptedKey);
            fis.close();

            byte[] decryptedKey = cipher.doFinal(encryptedKey);
            return new javax.crypto.spec.SecretKeySpec(decryptedKey, SYMMETRIC_ALGORITHM);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        String publicKeyFile = "public.key";
        String privateKeyFile = "private.key";
        String symmetricKeyFile = "symmetric.key";
        String encryptedKeyFile = "encrypted.key";

        generateKeyPair(publicKeyFile, privateKeyFile);

        Key symmetricKey = generateSymmetricKey();
        encryptSymmetricKey(publicKeyFile, symmetricKey, encryptedKeyFile);

        Key decryptedKey = decryptSymmetricKey(privateKeyFile, encryptedKeyFile);

        System.out.println("Original Symmetric Key: " + symmetricKey);
        System.out.println("Decrypted Symmetric Key: " + decryptedKey);
    }
}