import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class ECCEncryption4 {
    private static final String ALGORITHM = "EC";
    private static final String PROVIDER = "SunEC";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM, PROVIDER);
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        keyGen.initialize(256, random);
        return keyGen.generateKeyPair();
    }

    public static byte[] encrypt(byte[] plaintext, PublicKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION, PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
    }

    public static byte[] decrypt(byte[] ciphertext, PrivateKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION, PROVIDER);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(ciphertext);
    }

    public static void main(String[] args) throws Exception {
        // Generate key pair
        KeyPair keyPair = generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Encrypt the symmetric key
        String symmetricKey = "This is a symmetric key";
        byte[] encryptedKey = encrypt(symmetricKey.getBytes(), publicKey);
        System.out.println("Encrypted Symmetric Key: " + new String(encryptedKey));

        // Decrypt the symmetric key
        byte[] decryptedKey = decrypt(encryptedKey, privateKey);
        System.out.println("Decrypted Symmetric Key: " + new String(decryptedKey));
    }
}