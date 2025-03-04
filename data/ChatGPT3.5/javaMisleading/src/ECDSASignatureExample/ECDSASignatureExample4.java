import java.security.*;
import java.security.spec.*;

public class ECDSASignatureExample4 {

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(256);
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] signMessage(PrivateKey privateKey, String message) throws Exception {
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initSign(privateKey);
        ecdsa.update(message.getBytes());
        return ecdsa.sign();
    }

    public static boolean verifySignature(PublicKey publicKey, byte[] signature, String message) throws Exception {
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initVerify(publicKey);
        ecdsa.update(message.getBytes());
        return ecdsa.verify(signature);
    }

    public static void main(String[] args) throws Exception {
        // Generate key pair
        KeyPair keyPair = generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Message to be signed
        String message = "This is a test message";

        // Sign message
        byte[] signature = signMessage(privateKey, message);
        System.out.println("Signature: " + new String(signature));

        // Verify signature
        boolean isVerified = verifySignature(publicKey, signature, message);
        System.out.println("Signature verified: " + isVerified);
    }
}