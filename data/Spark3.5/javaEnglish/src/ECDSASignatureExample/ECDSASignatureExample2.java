import java.security.*;
import java.util.Arrays;

public class ECDSASignatureExample2 {
    public static void main(String[] args) throws Exception {
        // Generate key pair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();
        PublicKey publicKey = kp.getPublic();
        PrivateKey privateKey = kp.getPrivate();

        // Message to be signed
        String message = "Hello, World!";

        // Sign the message
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initSign(privateKey);
        ecdsa.update(message.getBytes("UTF-8"));
        byte[] signature = ecdsa.sign();
        System.out.println("Signature: " + Arrays.toString(signature));

        // Verify the signature
        ecdsa.initVerify(publicKey);
        ecdsa.update(message.getBytes("UTF-8"));
        boolean isVerified = ecdsa.verify(signature);
        System.out.println("Signature verified: " + isVerified);
    }
}