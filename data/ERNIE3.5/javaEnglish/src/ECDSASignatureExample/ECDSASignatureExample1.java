import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class ECDSASignatureExample1 {

    public static void main(String[] args) throws Exception {
        // Generate EC key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Message to be signed
        String message = "Hello, ECDSA!";

        // Sign the message
        Signature ecdsaSigner = Signature.getInstance("SHA256withECDSA");
        ecdsaSigner.initSign(privateKey);
        ecdsaSigner.update(message.getBytes(UTF_8));
        byte[] signature = ecdsaSigner.sign();

        // Verify the signature
        Signature ecdsaVerifier = Signature.getInstance("SHA256withECDSA");
        ecdsaVerifier.initVerify(publicKey);
        ecdsaVerifier.update(message.getBytes(UTF_8));
        boolean isVerified = ecdsaVerifier.verify(signature);

        // Output the results
        System.out.println("Signature: " + Base64.getEncoder().encodeToString(signature));
        System.out.println("Is Verified: " + isVerified);
    }
}