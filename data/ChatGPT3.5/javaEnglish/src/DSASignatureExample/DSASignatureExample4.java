import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class DSASignatureExample4 {

    public static void main(String[] args) {
        try {
            // Generate DSA key pair
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
            keyGen.initialize(1024);
            KeyPair keyPair = keyGen.generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            // Create a DSA signature object
            Signature dsa = Signature.getInstance("SHA1withDSA");

            // Initializing the signature object with the private key
            dsa.initSign(privateKey);

            // Message to be signed
            String message = "Hello, this is a message to be signed.";

            // Update the signature object with the data to be signed
            dsa.update(message.getBytes());

            // Sign the data and generate the signature
            byte[] signature = dsa.sign();

            System.out.println("Signature generated: " + new String(signature));

            // Initializing the signature object with the public key
            dsa.initVerify(publicKey);

            // Verify the signature with the original message
            dsa.update(message.getBytes());

            boolean verified = dsa.verify(signature);
            if (verified) {
                System.out.println("Signature verified successfully.");
            } else {
                System.out.println("Invalid signature.");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}