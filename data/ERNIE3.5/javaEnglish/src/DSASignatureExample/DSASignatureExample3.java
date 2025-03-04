import java.security.*;

import static java.nio.charset.StandardCharsets.UTF_8;

public class DSASignatureExample3 {

    public static void main(String[] args) throws Exception {
        // Generate DSA key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Message to be signed
        String message = "Hello, DSA!";

        // Sign the message
        Signature dsaSigner = Signature.getInstance("SHA256withDSA");
        dsaSigner.initSign(privateKey);
        dsaSigner.update(message.getBytes(UTF_8));
        byte[] signature = dsaSigner.sign();

        // Verify the signature
        Signature dsaVerifier = Signature.getInstance("SHA256withDSA");
        dsaVerifier.initVerify(publicKey);
        dsaVerifier.update(message.getBytes(UTF_8));
        boolean isVerified = dsaVerifier.verify(signature);

        System.out.println("Signature Verified: " + isVerified);
    }
}