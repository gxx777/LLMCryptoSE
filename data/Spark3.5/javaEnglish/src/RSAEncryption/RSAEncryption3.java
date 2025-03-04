import java.security.*;
import javax.crypto.*;
import java.util.Base64;

public class RSAEncryption3 {
    private static final String RSA = "RSA";
    private static final String AES = "AES";
    private static final int KEY_SIZE = 2048;

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
        keyPairGenerator.initialize(KEY_SIZE);
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] encrypt(byte[] data, PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] data, PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    public static void main(String[] args) {
        try {
            // Generate key pair
            KeyPair keyPair = generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // Encrypt the symmetric key
            String symmetricKey = "ThisIsASymmetricKey";
            byte[] encryptedSymmetricKey = encrypt(symmetricKey.getBytes(), publicKey);
            System.out.println("Encrypted Symmetric Key: " + Base64.getEncoder().encodeToString(encryptedSymmetricKey));

            // Decrypt the symmetric key
            byte[] decryptedSymmetricKey = decrypt(encryptedSymmetricKey, privateKey);
            System.out.println("Decrypted Symmetric Key: " + new String(decryptedSymmetricKey));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}