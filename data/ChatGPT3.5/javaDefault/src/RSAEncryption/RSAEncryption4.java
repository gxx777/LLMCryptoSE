import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RSAEncryption4 {

    public static void main(String[] args) throws Exception {
        String input = "This is a secret message";
        byte[] symmetricKey = generateSymmetricKey();
        encryptSymmetricKey(symmetricKey);

        byte[] encryptedData = encryptData(input, symmetricKey);
        String decryptedData = decryptData(encryptedData, symmetricKey);

        System.out.println("Decrypted data: " + decryptedData);
    }

    private static byte[] generateSymmetricKey() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        byte[] symmetricKey = publicKey.getEncoded();
        writeKeyToFile("symmetric.key", symmetricKey);
        return symmetricKey;
    }

    private static void encryptSymmetricKey(byte[] symmetricKey) throws Exception {
        byte[] keyBytes = readKeyFromFile("symmetric.key");
        PrivateKey privateKey = getPrivateKey(keyBytes);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] encryptedSymmetricKey = cipher.doFinal(symmetricKey);
        writeKeyToFile("encryptedSymmetric.key", encryptedSymmetricKey);
    }

    private static byte[] encryptData(String input, byte[] symmetricKey) throws Exception {
        SecretKey secretKey = new SecretKeySpec(symmetricKey, 0, symmetricKey.length, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(input.getBytes());
    }

    private static String decryptData(byte[] encryptedData, byte[] symmetricKey) throws Exception {
        SecretKey secretKey = new SecretKeySpec(symmetricKey, 0, symmetricKey.length, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedData = cipher.doFinal(encryptedData);
        return new String(decryptedData);
    }

    private static void writeKeyToFile(String fileName, byte[] key) throws IOException {
        FileOutputStream fos = new FileOutputStream(fileName);
        fos.write(key);
        fos.close();
    }

    private static byte[] readKeyFromFile(String fileName) throws IOException {
        File file = new File(fileName);
        FileInputStream fis = new FileInputStream(file);
        byte[] keyBytes = new byte[(int) file.length()];
        fis.read(keyBytes);
        fis.close();
        return keyBytes;
    }

    private static PrivateKey getPrivateKey(byte[] keyBytes) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        return privateKey;
    }
}