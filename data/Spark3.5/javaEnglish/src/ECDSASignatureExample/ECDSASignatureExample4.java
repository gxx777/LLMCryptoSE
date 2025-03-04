import java.security.*;
import java.util.Arrays;

public class ECDSASignatureExample4 {
    private static final String SHA_256_WITH_ECDSA = "SHA256withECDSA";

    public static void main(String[] args) throws Exception {
        // Generate key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        KeyPair keyPair = keyGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Sign message
        String message = "Hello, World!";
        byte[] signature = signMessage(privateKey, message);
        System.out.println("Signature: " + Arrays.toString(signature));

        // Verify message
        boolean isVerified = verifySignature(publicKey, message, signature);
        System.out.println("Signature verified: " + isVerified);
    }

    public static byte[] signMessage(PrivateKey privateKey, String message) throws Exception {
        Signature ecdsaSign = Signature.getInstance(SHA_256_WITH_ECDSA);
        ecdsaSign.initSign(privateKey);
        ecdsaSign.update(message.getBytes("UTF-8"));
        return ecdsaSign.sign();
    }

    public static boolean verifySignature(PublicKey publicKey, String message, byte[] signature) throws Exception {
        Signature ecdsaVerify = Signature.getInstance(SHA_256_WITH_ECDSA);
        ecdsaVerify.initVerify(publicKey);
        ecdsaVerify.update(message.getBytes("UTF-8"));
        return ecdsaVerify.verify(signature);
    }
}