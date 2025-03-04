import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class ECDSASignatureExample2 {

    private static final String ALGORITHM = "SHA256withECDSA";

    public static void main(String[] args) throws Exception {
        // Generate key pair
        KeyPair keyPair = generateKeyPair();

        // Message to be signed
        String message = "Hello, ECDSA!";

        // Sign the message
        byte[] signature = signMessage(message, keyPair.getPrivate());
        System.out.println("Signature: " + Base64.getEncoder().encodeToString(signature));

        // Verify the signature
        boolean isVerified = verifySignature(message, signature, keyPair.getPublic());
        System.out.println("Signature verified: " + isVerified);
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(256);
        return keyPairGenerator.generateKeyPair();
    }

    private static byte[] signMessage(String message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance(ALGORITHM);
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        return signature.sign();
    }

    private static boolean verifySignature(String message, byte[] signature, PublicKey publicKey) throws Exception {
        Signature verifySignature = Signature.getInstance(ALGORITHM);
        verifySignature.initVerify(publicKey);
        verifySignature.update(message.getBytes());
        return verifySignature.verify(signature);
    }
}