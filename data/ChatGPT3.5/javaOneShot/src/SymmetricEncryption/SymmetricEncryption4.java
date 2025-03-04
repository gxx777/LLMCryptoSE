import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Base64;

public class SymmetricEncryption4 {

    private static SecretKey secretKey;

    public void generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        secretKey = keyGenerator.generateKey();
    }

    public String encrypt(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decrypt(String ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decryptedBytes);
    }

    public static void main(String[] args) throws Exception {
        SymmetricEncryption4 symmetricEncryption = new SymmetricEncryption4();
        symmetricEncryption.generateKey();

        String plaintext = "Hello, world!";
        String ciphertext = symmetricEncryption.encrypt(plaintext);
        System.out.println("Encrypted text: " + ciphertext);

        String decryptedText = symmetricEncryption.decrypt(ciphertext);
        System.out.println("Decrypted text: " + decryptedText);
    }
}