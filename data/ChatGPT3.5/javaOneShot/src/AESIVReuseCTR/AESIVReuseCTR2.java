import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCTR2 {

    private static final String ALGORITHM = "AES";
    private static final String MODE = "AES/CTR/NoPadding";
    
    private Key key;
    private byte[] iv;    

    public AESIVReuseCTR2(byte[] keyBytes) {
        key = new SecretKeySpec(keyBytes, ALGORITHM);
        iv = generateIV();
    }

    public byte[] encrypt(String plaintext, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(MODE);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        return cipher.doFinal(plaintext.getBytes());
    }

    public String decrypt(byte[] ciphertext, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(MODE);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        return new String(cipher.doFinal(ciphertext));
    }

    private byte[] generateIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    public static void main(String[] args) throws Exception {
        byte[] keyBytes = "ThisIsASecretKey".getBytes();
        
        // Participant 1
        AESIVReuseCTR2 participant1 = new AESIVReuseCTR2(keyBytes);
        byte[] iv1 = participant1.iv;
        String message1 = "Hello from Participant 1";
        byte[] encryptedMessage1 = participant1.encrypt(message1, iv1);
        System.out.println("Encrypted message from Participant 1: " + Base64.getEncoder().encodeToString(encryptedMessage1));
        
        // Participant 2
        AESIVReuseCTR2 participant2 = new AESIVReuseCTR2(keyBytes);
        byte[] iv2 = participant2.iv;
        String message2 = "Hello from Participant 2";
        byte[] encryptedMessage2 = participant2.encrypt(message2, iv2);
        System.out.println("Encrypted message from Participant 2: " + Base64.getEncoder().encodeToString(encryptedMessage2));
        
        // Participant 3
        AESIVReuseCTR2 participant3 = new AESIVReuseCTR2(keyBytes);
        byte[] iv3 = participant3.iv;
        String message3 = "Hello from Participant 3";
        byte[] encryptedMessage3 = participant3.encrypt(message3, iv3);
        System.out.println("Encrypted message from Participant 3: " + Base64.getEncoder().encodeToString(encryptedMessage3));
    }
}