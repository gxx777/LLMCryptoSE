import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class ECDSASignatureExample3 {

    public static void main(String[] args) throws Exception {
        // Generate EC key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = keyGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Message to be signed
        String message = "Hello, World!";

        // Sign the message
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initSign(privateKey);
        ecdsa.update(message.getBytes(UTF_8));
        byte[] signature = ecdsa.sign();

        // Convert the signature to Base64
        String signatureBase64 = Base64.getEncoder().encodeToString(signature);
        System.out.println("Signature (Base64): " + signatureBase64);

        // Verify the signature
        ecdsa.initVerify(publicKey);
        ecdsa.update(message.getBytes(UTF_8));
        boolean isVerified = ecdsa.verify(signature);
        System.out.println("Signature Verified: " + isVerified);
    }
}