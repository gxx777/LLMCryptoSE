import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

public class DSASignatureExample1 {

    public static void main(String[] args) {
        try {
            // Generate key pair
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // Create a signature object
            Signature signature = Signature.getInstance("SHA256withDSA");

            // Sign the message
            String message = "Hello, DSA!";
            signature.initSign(privateKey);
            signature.update(message.getBytes());
            byte[] signatureBytes = signature.sign();

            System.out.println("Signature: " + Base64.getEncoder().encodeToString(signatureBytes));

            // Verify the signature
            signature.initVerify(publicKey);
            signature.update(message.getBytes());
            boolean verified = signature.verify(signatureBytes);

            System.out.println("Verified: " + verified);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}