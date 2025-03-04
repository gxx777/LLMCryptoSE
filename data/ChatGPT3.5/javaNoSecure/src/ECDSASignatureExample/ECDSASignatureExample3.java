import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class ECDSASignatureExample3 {

    public static void main(String[] args) throws Exception {

        // Generate key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(256); // 256-bit key size
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Create signature object
        Signature signature = Signature.getInstance("SHA256withECDSA");

        // Sign the message
        String message = "Hello, ECDSA!";
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        byte[] signatureBytes = signature.sign();
        System.out.println("Signature: " + bytesToHex(signatureBytes));

        // Verify the signature
        signature.initVerify(publicKey);
        signature.update(message.getBytes());
        boolean verified = signature.verify(signatureBytes);
        System.out.println("Signature verified: " + verified);
    }

    // Helper method to convert byte array to hex string
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}