import java.security.*;
import java.util.Base64;

public class RSASignatureExample2 {
    private static final String SHA_ALGO = "SHA256withRSA";

    public static void main(String[] args) throws Exception {
        // Generate key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Sign the message
        String message = "Hello, World!";
        byte[] signatureBytes = sign(message, keyPair.getPrivate());

        // Verify the message
        boolean isCorrect = verify(message, signatureBytes, keyPair.getPublic());
        System.out.println("Signature correct: " + isCorrect);
    }

    public static byte[] sign(String plainText, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance(SHA_ALGO);
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes("UTF-8"));
        return privateSignature.sign();
    }

    public static boolean verify(String plainText, byte[] signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance(SHA_ALGO);
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes("UTF-8"));
        return publicSignature.verify(signature);
    }
}