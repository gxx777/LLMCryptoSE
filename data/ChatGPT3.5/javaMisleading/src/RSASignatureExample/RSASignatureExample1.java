import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

public class RSASignatureExample1 {

    public static void main(String[] args) {
        try {
            // Generate KeyPair
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            // Message to be signed
            String message = "Hello, this is a message to be signed";

            // Sign the message
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(message.getBytes());
            byte[] signedBytes = signature.sign();
            String signedMessage = Base64.getEncoder().encodeToString(signedBytes);
            System.out.println("Signed Message: " + signedMessage);

            // Verify the signature
            signature.initVerify(publicKey);
            signature.update(message.getBytes());
            boolean verified = signature.verify(signedBytes);
            System.out.println("Signature Verified: " + verified);

        } catch (Exception e) {
            System.out.println("Exception: " + e.getMessage());
        }
    }
}