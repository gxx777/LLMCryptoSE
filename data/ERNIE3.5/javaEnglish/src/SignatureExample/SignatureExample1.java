import java.security.*;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class SignatureExample1 {

    public static void main(String[] args) throws Exception {
        // Generate RSA key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Message to be signed
        String message = "Hello, World!";

        // Sign the message
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes(UTF_8));
        byte[] signatureBytes = signature.sign();

        // Base64 encode the signature
        String signatureBase64 = Base64.getEncoder().encodeToString(signatureBytes);
        System.out.println("Signature (Base64): " + signatureBase64);

        // Verify the signature
        signature.initVerify(publicKey);
        signature.update(message.getBytes(UTF_8));
        boolean isVerified = signature.verify(signatureBytes);
        System.out.println("Signature Verified: " + isVerified);
    }
}