import javax.crypto.Cipher;
import java.io.*;
import java.security.*;

public class RSAEncryption2 {
    private static final String ALGORITHM = "RSA";
    private static final int KEY_SIZE = 2048;

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(KEY_SIZE);
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] encrypt(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    public static void writeEncryptedKeyToFile(byte[] encryptedKey, String filePath) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(encryptedKey);
        }
    }

    public static byte[] readEncryptedKeyFromFile(String filePath) throws IOException {
        byte[] encryptedKey;
        try (FileInputStream fis = new FileInputStream(filePath)) {
            encryptedKey = new byte[fis.available()];
            fis.read(encryptedKey);
        }
        return encryptedKey;
    }
}