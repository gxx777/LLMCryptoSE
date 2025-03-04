import java.nio.charset.StandardCharsets;
import java.security.*;

public class DSASignatureExample2 {

    public static void main(String[] args) throws Exception {
        // Generate DSA key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Message to be signed
        String message = "Hello, DSA!";

        // Sign the message
        Signature dsaSigner = Signature.getInstance("SHA256withDSA");
        dsaSigner.initSign(privateKey);
        dsaSigner.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signature = dsaSigner.sign();

        // Verify the signature
        Signature dsaVerifier = Signature.getInstance("SHA256withDSA");
        dsaVerifier.initVerify(publicKey);
        dsaVerifier.update(message.getBytes(StandardCharsets.UTF_8));
        boolean isVerified = dsaVerifier.verify(signature);

        System.out.println("Signature Verified: " + isVerified);
    }
}