import java.security.*;
import java.util.Base64;

public class RSASignatureExample4 {
    private static final String SIGNING_ALGORITHM = "SHA256withRSA";

    public static byte[] sign(String plainText, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance(SIGNING_ALGORITHM);
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes("UTF-8"));
        return privateSignature.sign();
    }

    public static boolean verify(String plainText, byte[] signatureToVerify, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance(SIGNING_ALGORITHM);
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes("UTF-8"));
        return publicSignature.verify(signatureToVerify);
    }

    public static void main(String[] args) throws Exception {
        // Generate key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Sign the message
        String msg = "Hello, World!";
        byte[] signature = sign(msg, keyPair.getPrivate());

        // Verify the message
        boolean isCorrect = verify(msg, signature, keyPair.getPublic());
        System.out.println("Signature correct: " + isCorrect);
    }
}