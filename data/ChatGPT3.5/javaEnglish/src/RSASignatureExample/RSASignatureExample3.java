import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class RSASignatureExample3 {

    public static void main(String[] args) throws Exception {
        // Generate key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Create a Signature object
        Signature signature = Signature.getInstance("SHA256withRSA");

        // Signing the message
        byte[] message = "Hello, World!".getBytes();
        signature.initSign(privateKey);
        signature.update(message);
        byte[] digitalSignature = signature.sign();
        System.out.println("Signature: " + new String(digitalSignature));

        // Verifying the signature
        signature.initVerify(publicKey);
        signature.update(message);
        boolean verified = signature.verify(digitalSignature);
        System.out.println("Signature verified: " + verified);
    }
}