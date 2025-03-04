import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SymmetricEncryptionCBC1 {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";

    public static byte[] encrypt(String key, String initVector, String data) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKey secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
        AlgorithmParameterSpec spec = new IvParameterSpec(initVector.getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        return cipher.doFinal(data.getBytes());
    }

    public static String decrypt(String key, String initVector, byte[] encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKey secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
        AlgorithmParameterSpec spec = new IvParameterSpec(initVector.getBytes());
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        byte[] decryptedData = cipher.doFinal(encryptedData);
        return new String(decryptedData);
    }

    public static void main(String[] args) {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
            keyGen.init(128, new SecureRandom());
            Key key = keyGen.generateKey();
            String keyString = new String(Base64.getEncoder().encode(key.getEncoded()));

            String initVector = "RandomInitVector";
            String data = "Hello, World!";
            
            byte[] encryptedData = encrypt(keyString, initVector, data);
            System.out.println("Encrypted Data: " + new String(encryptedData));

            String decryptedData = decrypt(keyString, initVector, encryptedData);
            System.out.println("Decrypted Data: " + decryptedData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}