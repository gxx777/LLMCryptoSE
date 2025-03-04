import java.security.*;
import java.util.Base64;

public class SignatureExample2 {
    public static void main(String[] args) {
        try {
            // Generate key pair
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // Message to be signed
            String message = "Hello, this is a message to be signed!";

            // Sign the message
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(message.getBytes());
            byte[] signedMessage = signature.sign();
            String signedMessageBase64 = Base64.getEncoder().encodeToString(signedMessage);
            System.out.println("Signed message (Base64): " + signedMessageBase64);

            // Verify the signature
            signature.initVerify(publicKey);
            signature.update(message.getBytes());
            boolean isVerified = signature.verify(signedMessage);
            System.out.println("Signature verification result: " + isVerified);

        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
    }
}