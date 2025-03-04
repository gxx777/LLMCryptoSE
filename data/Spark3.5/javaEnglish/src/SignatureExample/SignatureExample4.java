import java.security.*;
import java.util.Base64;

public class SignatureExample4 {
    private static final String ALGORITHM = "SHA256withRSA";

    public static void main(String[] args) throws Exception {
        // Generate key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Sign the message
        String message = "Hello, World!";
        Signature signature = Signature.getInstance(ALGORITHM);
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        byte[] signedMessage = signature.sign();
        System.out.println("Signed Message: " + Base64.getEncoder().encodeToString(signedMessage));

        // Verify the message
        signature.initVerify(publicKey);
        signature.update(message.getBytes());
        boolean isVerified = signature.verify(signedMessage);
        System.out.println("Is Verified: " + isVerified);
    }
}