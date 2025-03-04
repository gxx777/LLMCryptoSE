import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.Base64;

public class ECDSASignatureExample4 {

    public static void main(String[] args) throws Exception {
        // Generate ECDSA key pair
        KeyPair keyPair = generateECDSAKeyPair();

        // Message to be signed
        String message = "Hello, this is a test message!";

        // Sign the message
        String signature = signMessage(message, keyPair.getPrivate());

        // Verify the signature
        boolean isVerified = verifySignature(message, signature, keyPair.getPublic());

        System.out.println("Signature: " + signature);
        System.out.println("Is Verified: " + isVerified);
    }

    private static KeyPair generateECDSAKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
        return keyPairGenerator.generateKeyPair();
    }

    private static String signMessage(String message, PrivateKey privateKey) throws Exception {
        Signature ecdsaSignature = Signature.getInstance("SHA256withECDSA");
        ecdsaSignature.initSign(privateKey);
        ecdsaSignature.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = ecdsaSignature.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    private static boolean verifySignature(String message, String signature, PublicKey publicKey) throws Exception {
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        Signature ecdsaSignature = Signature.getInstance("SHA256withECDSA");
        ecdsaSignature.initVerify(publicKey);
        ecdsaSignature.update(message.getBytes(StandardCharsets.UTF_8));
        return ecdsaSignature.verify(signatureBytes);
    }
}