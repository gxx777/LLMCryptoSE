import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseGCM4 {

    public static void main(String[] args) throws Exception {
        // Generate a random 256-bit AES key
        byte[] keyBytes = new byte[32];
        SecureRandom random = new SecureRandom();
        random.nextBytes(keyBytes);
        SecretKey key = new SecretKeySpec(keyBytes, "AES");

        // Create a GCM cipher instance
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        // Participant A encrypts a message for Participant B
        byte[] iv = new byte[12];
        random.nextBytes(iv);
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] ciphertextAB = cipher.doFinal("Hello, Participant B!".getBytes());

        // Participant B encrypts a message for Participant A
        iv = new byte[12];
        random.nextBytes(iv);
        spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] ciphertextBA = cipher.doFinal("Hello, Participant A!".getBytes());

        // Participant C encrypts a message for Participant A and Participant B
        iv = new byte[12];
        random.nextBytes(iv);
        spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] ciphertextC = cipher.doFinal("Hello, Participants A and B!".getBytes());

        // Decrypt and print the messages sent to each participant
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, ciphertextAB, 0, 12));
        System.out.println("Participant B received: " + new String(cipher.doFinal(ciphertextAB, 12, ciphertextAB.length - 12)));

        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, ciphertextBA, 0, 12));
        System.out.println("Participant A received: " + new String(cipher.doFinal(ciphertextBA, 12, ciphertextBA.length - 12)));

        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, ciphertextC, 0, 12));
        System.out.println("Participants A and B received: " + new String(cipher.doFinal(ciphertextC, 12, ciphertextC.length - 12)));
    }

}