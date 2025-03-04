import javax.crypto.Cipher;
import java.security.*;
import java.util.Base64;

public class RSAEncryption2 {
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public RSAEncryption2() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();
    }

    public String encrypt(String plainText) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decrypt(String encryptedText) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        try {
            RSAEncryption2 rsaEncryption2 = new RSAEncryption2();
            String plainText = "This is a secret message";
            System.out.println("Original Text: " + plainText);
            String encryptedText = rsaEncryption2.encrypt(plainText);
            System.out.println("Encrypted Text: " + encryptedText);
            String decryptedText = rsaEncryption2.decrypt(encryptedText);
            System.out.println("Decrypted Text: " + decryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}