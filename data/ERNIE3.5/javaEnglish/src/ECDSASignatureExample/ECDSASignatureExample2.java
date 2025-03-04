import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.Base64;

public class ECDSASignatureExample2 {

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
        ecdsaSigner.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signature = ecdsaSigner.sign();

        // Convert signature to Base64
        String signatureBase64 = Base64.getEncoder().encodeToString(signature);
        System.out.println("Signature (Base64): " + signatureBase64);

        // Verify the signature
        Signature ecdsaVerifier = Signature.getInstance("SHA256withECDSA");
        ecdsaVerifier.initVerify(publicKey);
        ecdsaVerifier.update(message.getBytes(StandardCharsets.UTF_8));
        boolean isVerified = ecdsaVerifier.verify(signature);

        System.out.println("Signature Verified: " + isVerified);
    }
}