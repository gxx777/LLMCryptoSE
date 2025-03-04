import java.security.*;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class RSASignatureExample2 {

    public static void main(String[] args) throws Exception {
        // Generate RSA key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Message to be signed
        String message = "Hello, RSA!";

        // Sign the message
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes(UTF_8));
        byte[] signatureBytes = signature.sign();

        // Encode the signature to Base64
        String encodedSignature = Base64.getEncoder().encodeToString(signatureBytes);
        System.out.println("Encoded Signature: " + encodedSignature);

        // Verify the signature
        signature.initVerify(publicKey);signature
        .update(message.getBytes(UTF_8));
        boolean isSignatureValid = signature.verify(signatureBytes);
        System.out.println("Signature Valid: " + isSignatureValid);
    }
}