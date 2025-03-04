import java.security.*;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class ECCEncryption2 {
    private static final String ALGORITHM = "EC";
    private static final String CURVE = "secp256r1";
    private static final String AES_ALGORITHM = "AES";
    private static final int AES_KEY_SIZE = 128;

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(CURVE);
        keyPairGenerator.initialize(ecGenParameterSpec);
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] encryptSymmetricKey(byte[] symmetricKey, PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(symmetricKey);
    }

    public static byte[] decryptSymmetricKey(byte[] encryptedSymmetricKey, PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedSymmetricKey);
    }

    public static SecretKeySpec generateAESKey() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] key = new byte[AES_KEY_SIZE / 8];
        secureRandom.nextBytes(key);
        return new SecretKeySpec(key, AES_ALGORITHM);
    }

    public static byte[] encryptData(byte[] data, SecretKey secretKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }

    public static byte[] decryptData(byte[] encryptedData, SecretKey secretKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(encryptedData);
    }

    public static void main(String[] args) throws Exception {
        // Generate ECC key pair
        KeyPair keyPair = generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Generate AES key
        SecretKey secretKey = generateAESKey();

        // Encrypt the AES key using ECC public key
        byte[] encryptedSymmetricKey = encryptSymmetricKey(secretKey.getEncoded(), publicKey);
        System.out.println("Encrypted symmetric key: " + Base64.getEncoder().encodeToString(encryptedSymmetricKey));

        // Decrypt the AES key using ECC private key
        byte[] decryptedSymmetricKey = decryptSymmetricKey(encryptedSymmetricKey, privateKey);
        System.out.println("Decrypted symmetric key: " + Base64.getEncoder().encodeToString(decryptedSymmetricKey));

        // Encrypt some data using the AES key
        String data = "Hello, world!";
        byte[] encryptedData = encryptData(data.getBytes(), secretKey);
        System.out.println("Encrypted data: " + Base64.getEncoder().encodeToString(encryptedData));

        // Decrypt the data using the AES key
        byte[] decryptedData = decryptData(encryptedData, secretKey);
        System.out.println("Decrypted data: " + new String(decryptedData));
    }
}