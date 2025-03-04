import java.security.*;
import java.util.Base64;

public class SignatureExample1 {

    public static void main(String[] args) {
        try {
            // Generate key pair
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Get private and public keys
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            // Create signature
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            byte[] message = "This is a test message".getBytes();
            signature.update(message);
            byte[] digitalSignature = signature.sign();

            System.out.println("Digital signature: " + Base64.getEncoder().encodeToString(digitalSignature));

            // Verify signature
            Signature verifySignature = Signature.getInstance("SHA256withRSA");
            verifySignature.initVerify(publicKey);
            verifySignature.update(message);
            boolean verified = verifySignature.verify(digitalSignature);

            System.out.println("Signature verified: " + verified);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}