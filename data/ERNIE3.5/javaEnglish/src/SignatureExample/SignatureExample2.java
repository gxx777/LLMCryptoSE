import java.security.*;

import static java.nio.charset.StandardCharsets.UTF_8;

public class SignatureExample2 {

    public static void main(String[] args) throws Exception {
        // Generate a key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Message to be signed
        String message = "Hello, this is a signed message!";

        // Sign the message
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes(UTF_8));
        byte[] signatureBytes = signature.sign();

        // Verify the signature
        signature.initVerify(publicKey);
        signature.update(message.getBytes(UTF_8));
        boolean isValid = signature.verify(signatureBytes);

        System.out.println("Signature is valid: " + isValid);
    }
}