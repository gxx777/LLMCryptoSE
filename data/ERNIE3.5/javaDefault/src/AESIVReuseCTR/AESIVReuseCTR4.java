import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESIVReuseCTR4 {

    private static final String ALGORITHM = "AES/CTR/NoPadding";
    private static final int KEY_SIZE = 128;

    private SecretKey key;
    private IvParameterSpec iv;

    public AESIVReuseCTR4() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(KEY_SIZE, new SecureRandom());
        this.key = keyGenerator.generateKey();

        // Note: Reusing the IV is not secure. It is done here as per the requirement.
        byte[] ivBytes = new byte[16]; // AES CTR mode requires a 16-byte IV
        new SecureRandom().nextBytes(ivBytes);
        this.iv = new IvParameterSpec(ivBytes);
    }

    public String encrypt(String plainText, String partyIdentifier) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes) + "|" + partyIdentifier;
    }

    public String decrypt(String encryptedText, String partyIdentifier) throws Exception {
        // Assuming the encryptedText contains the party identifier as a suffix, separated by '|'
        String[] parts = encryptedText.split("\\|");
        if (parts.length != 2 || !parts[1].equals(partyIdentifier)) {
            throw new Exception("Invalid encrypted text or party identifier");
        }

        byte[] encryptedBytes = Base64.getDecoder().decode(parts[0]);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        try {
            AESIVReuseCTR4 aesCtr = new AESIVReuseCTR4();

            // Encrypt messages for each party
            String messageForParty1 = "Hello Party 1";
            String encryptedMessageForParty1 = aesCtr.encrypt(messageForParty1, "Party1");
            System.out.println("Encrypted message for Party 1: " + encryptedMessageForParty1);

            String messageForParty2 = "Hello Party 2";
            String encryptedMessageForParty2 = aesCtr.encrypt(messageForParty2, "Party2");
            System.out.println("Encrypted message for Party 2: " + encryptedMessageForParty2);

            // Decrypt messages for each party
            String decryptedMessageForParty1 = aesCtr.decrypt(encryptedMessageForParty1, "Party1");
            System.out.println("Decrypted message for Party 1: " + decryptedMessageForParty1);

            String decryptedMessageForParty2 = aesCtr.decrypt(encryptedMessageForParty2, "Party2");
            System.out.println("Decrypted message for Party 2: " + decryptedMessageForParty2);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}