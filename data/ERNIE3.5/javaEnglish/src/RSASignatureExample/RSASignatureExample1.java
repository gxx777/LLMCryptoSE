import java.security.*;
import java.util.Base64;

public class RSASignatureExample1 {

    public static void main(String[] args) throws Exception {
        // Generate RSA key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Message to be signed
        String message = "Hello, RSA!";

        // Sign the message
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey);
        signer.update(message.getBytes(UTF_8));
        byte[] signature = signer.sign();

        // Verify the signature
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKey);
        verifier.update(message.getBytes(UTF_8));
        boolean isValid = verifier.verify(signature);

        System.out.println("Signature is valid: " + isValid);
    }

    private static final String UTF_8 = "UTF-8";
}