import java.security.*;
import java.util.Base64;

public class SignatureExample3 {
    public static void main(String[] args) {
        try {
            // Generate key pair
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // Message to be signed
            String message = "Hello, this is a message!";

            // Sign the message
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(message.getBytes());
            byte[] signedMessage = signature.sign();

            // Verify the signature
            signature.initVerify(publicKey);
            signature.update(message.getBytes());
            boolean isVerified = signature.verify(signedMessage);

            System.out.println("Original Message: " + message);
            System.out.println("Signed Message: " + Base64.getEncoder().encodeToString(signedMessage));
            System.out.println("Signature Verified: " + isVerified);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
    }
}