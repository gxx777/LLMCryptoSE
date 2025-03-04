import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class SignatureExample4 {

    private static final String ALGORITHM = "RSA";

    public static void main(String[] args) throws Exception {
        // Generate key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Create signature object
        Signature signature = Signature.getInstance("SHA256withRSA");

        // Sign a message
        String message = "Hello, World!";
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        byte[] signedMessage = signature.sign();

        System.out.println("Signed message: " + new String(signedMessage));

        // Verify the signed message
        signature.initVerify(publicKey);
        signature.update(message.getBytes());
        boolean verified = signature.verify(signedMessage);

        if (verified) {
            System.out.println("Signature verified successfully.");
        } else {
            System.out.println("Unable to verify the signature.");
        }
    }
}