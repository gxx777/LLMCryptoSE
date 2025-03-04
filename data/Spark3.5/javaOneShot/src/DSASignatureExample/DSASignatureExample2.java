import java.security.*;
import java.util.Base64;

public class DSASignatureExample2 {
    private static final int KEY_SIZE = 2048;

    public static void main(String[] args) {
        try {
            // Generate key pair
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
            keyPairGenerator.initialize(KEY_SIZE);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // Sign the message
            String message = "Hello, this is a signed message!";
            Signature signature = Signature.getInstance("SHA256withDSA");
            signature.initSign(privateKey);
            signature.update(message.getBytes());
            byte[] signedMessage = signature.sign();
            String signedMessageBase64 = Base64.getEncoder().encodeToString(signedMessage);
            System.out.println("Signed message: " + signedMessageBase64);

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