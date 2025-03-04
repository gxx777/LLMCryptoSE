import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class ECDSASignatureExample1 {

    public static void main(String[] args) throws Exception {
        // Generate key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(256);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Create a Signature object
        Signature signature = Signature.getInstance("SHA256withECDSA");

        // Initialize the Signature object for signing
        signature.initSign(privateKey);

        // Sign the message
        String message = "Hello, World!";
        signature.update(message.getBytes());
        byte[] signatureBytes = signature.sign();

        System.out.println("Signature: " + bytesToHex(signatureBytes));

        // Initialize the Signature object for verification
        signature.initVerify(publicKey);

        // Verify the signature
        signature.update(message.getBytes());
        boolean verified = signature.verify(signatureBytes);

        if (verified) {
            System.out.println("Signature verified");
        } else {
            System.out.println("Signature verification failed");
        }
    }

    // Helper method to convert byte array to hex string
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}