import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Base64;

public class AESIVReuseGCM2 {
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int IV_LENGTH = 12;

    public static void main(String[] args) throws Exception {
        // 生成密钥对
        KeyPair keyPair = generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // 发送方使用公钥加密消息
        String message = "Hello, this is a secret message!";
        byte[] encryptedMessage = encryptMessage(message, publicKey);
        System.out.println("Encrypted message: " + Base64.getEncoder().encodeToString(encryptedMessage));

        // 接收方使用私钥解密消息
        String decryptedMessage = decryptMessage(encryptedMessage, privateKey);
        System.out.println("Decrypted message: " + decryptedMessage);
    }

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] encryptMessage(String message, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, generateIV());
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, gcmParameterSpec);
        return cipher.doFinal(message.getBytes());
    }

    public static String decryptMessage(byte[] encryptedMessage, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, generateIV());
        cipher.init(Cipher.DECRYPT_MODE, privateKey, gcmParameterSpec);
        return new String(cipher.doFinal(encryptedMessage));
    }

    public static byte[] generateIV() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[IV_LENGTH];
        secureRandom.nextBytes(iv);
        return iv;
    }
}