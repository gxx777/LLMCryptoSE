import java.security.*;
import java.util.Base64;

public class RSASignatureExample1 {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // Generate key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Message to be signed
        String message = "Hello, this is a secure message!";

        // Sign the message
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        byte[] signedMessage = signature.sign();

        // Verify the message
        signature.initVerify(publicKey);
        signature.update(message.getBytes());
        boolean isVerified = signature.verify(signedMessage);

        // Print results
        System.out.println("Original Message: " + message);
        System.out.println("Signed Message (Base64): " + Base64.getEncoder().encodeToString(signedMessage));
        System.out.println("Verification Result: " + (isVerified ? "Success" : "Failed"));
    }
}