import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class DSASignatureExample2 {

    public static void main(String[] args) {
        try {
            // Generate key pair
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            // Message to be signed
            String message = "Hello, this is a message to be signed";

            // Create signature instance
            Signature signature = Signature.getInstance("SHA1withDSA");

            // Sign the message
            signature.initSign(privateKey);
            signature.update(message.getBytes());
            byte[] signatureBytes = signature.sign();
            System.out.println("Signature: " + new String(signatureBytes));

            // Verify the signature
            signature.initVerify(publicKey);
            signature.update(message.getBytes());
            boolean verified = signature.verify(signatureBytes);
            if (verified) {
                System.out.println("Signature verified");
            } else {
                System.out.println("Signature verification failed");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}