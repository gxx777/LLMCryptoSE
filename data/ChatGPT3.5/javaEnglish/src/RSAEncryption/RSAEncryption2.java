import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

public class RSAEncryption2 {

    private PublicKey publicKey;
    private PrivateKey privateKey;

    public RSAEncryption2() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            SecureRandom secureRandom = new SecureRandom();
            keyPairGenerator.initialize(2048, secureRandom);

            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public byte[] encrypt(byte[] input) {
        byte[] encryptedBytes = null;

        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            encryptedBytes = cipher.doFinal(input);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return encryptedBytes;
    }

    public byte[] decrypt(byte[] input) {
        byte[] decryptedBytes = null;

        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            decryptedBytes = cipher.doFinal(input);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return decryptedBytes;
    }

    public static void main(String[] args) {
        RSAEncryption2 rsaEncryption = new RSAEncryption2();

        String message = "Hello, RSA Encryption!";
        byte[] encrypted = rsaEncryption.encrypt(message.getBytes());
        System.out.println("Encrypted message: " + new String(encrypted));

        byte[] decrypted = rsaEncryption.decrypt(encrypted);
        System.out.println("Decrypted message: " + new String(decrypted));
    }
}