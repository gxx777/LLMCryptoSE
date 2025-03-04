// Importing necessary libraries
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class ECDSASignatureExample2 {

    public static void main(String[] args) {
        try {
            // Generate key pair
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(256); // key size
            KeyPair keyPair = keyGen.generateKeyPair();

            // Get private key
            PrivateKey privateKey = keyPair.getPrivate();

            // Get public key
            PublicKey publicKey = keyPair.getPublic();

            // Create signature
            Signature ecdsa = Signature.getInstance("SHA256withECDSA");
            ecdsa.initSign(privateKey);

            String message = "This is a message to be signed";
            ecdsa.update(message.getBytes());

            byte[] signature = ecdsa.sign();

            // Print signature
            System.out.println("Signature: " + Base64.getEncoder().encodeToString(signature));

            // Verify signature
            Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA");
            ecdsaVerify.initVerify(publicKey);
            ecdsaVerify.update(message.getBytes());

            boolean result = ecdsaVerify.verify(signature);

            System.out.println("Signature verified: " + result);

        } catch (Exception e) {
            System.err.println("Exception: " + e.getMessage());
        }
    }
}