import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class ECCEncryption4 {
    private static final String ALGORITHM = "EC";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final String PROVIDER = "SunJCE";
    private static final int KEY_SIZE = 256;

    public static void main(String[] args) throws Exception {
        // Generate ECC key pair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHM, PROVIDER);
        kpg.initialize(KEY_SIZE);
        KeyPair kp = kpg.generateKeyPair();
        PublicKey publicKey = kp.getPublic();
        PrivateKey privateKey = kp.getPrivate();

        // Encrypt the symmetric key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey secretKey = keyGen.generateKey();
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = cipher.doFinal(secretKey.getEncoded());

        // Decrypt the symmetric key
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedKey = cipher.doFinal(encryptedKey);
        SecretKey originalKey = new SecretKeySpec(decryptedKey, 0, decryptedKey.length, "AES");

        // Check if the original key is equal to the decrypted key
        System.out.println(java.util.Arrays.equals(secretKey.getEncoded(), originalKey.getEncoded()));
    }
}