import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class RSASignatureExample1 {

    public static void main(String[] args) throws Exception {
        // Generate key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Message to be signed
        String message = "Hello, World!";

        // Sign the message
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        byte[] signatureBytes = signature.sign();

        System.out.println("Signature: " + new String(signatureBytes));

        // Verify the signature
        signature.initVerify(publicKey);
        signature.update(message.getBytes());
        boolean verified = signature.verify(signatureBytes);

        if (verified) {
            System.out.println("Signature verified");
        } else {
            System.out.println("Signature not verified");
        }
    }
}