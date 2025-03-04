import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class AESIVReuseCBC3 {
    
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    
    private String key;
    private String iv;
    
    public AESIVReuseCBC3(String key, String iv) {
        this.key = key;
        this.iv = iv;
    }
    
    public String encrypt(String input) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            SecretKeySpec secretKeySpec = new SecretKeySpec(DatatypeConverter.parseHexBinary(key), ALGORITHM);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(DatatypeConverter.parseHexBinary(iv));
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] encrypted = cipher.doFinal(input.getBytes());
            return DatatypeConverter.printHexBinary(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    
    public String decrypt(String input) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            SecretKeySpec secretKeySpec = new SecretKeySpec(DatatypeConverter.parseHexBinary(key), ALGORITHM);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(DatatypeConverter.parseHexBinary(iv));
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] decrypted = cipher.doFinal(DatatypeConverter.parseHexBinary(input));
            return new String(decrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    
    public static void main(String[] args) {
        String key = "00112233445566778899AABBCCDDEEFF";
        String iv = "010203040506070809000A0B0C0D0E0F";
        
        AESIVReuseCBC3 sender1 = new AESIVReuseCBC3(key, iv);
        AESIVReuseCBC3 sender2 = new AESIVReuseCBC3(key, iv);
        AESIVReuseCBC3 sender3 = new AESIVReuseCBC3(key, iv);
        
        String message1 = "Message from sender 1";
        String encryptedMessage1 = sender1.encrypt(message1);
        
        String message2 = "Message from sender 2";
        String encryptedMessage2 = sender2.encrypt(message2);
        
        String message3 = "Message from sender 3";
        String encryptedMessage3 = sender3.encrypt(message3);
        
        System.out.println("Encrypted message from sender 1: " + encryptedMessage1);
        System.out.println("Decrypted message from sender 1: " + sender1.decrypt(encryptedMessage1));
        
        System.out.println("Encrypted message from sender 2: " + encryptedMessage2);
        System.out.println("Decrypted message from sender 2: " + sender2.decrypt(encryptedMessage2));
        
        System.out.println("Encrypted message from sender 3: " + encryptedMessage3);
        System.out.println("Decrypted message from sender 3: " + sender3.decrypt(encryptedMessage3));
    }
}