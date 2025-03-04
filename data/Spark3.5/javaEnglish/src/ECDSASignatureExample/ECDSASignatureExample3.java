import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

public class ECDSASignatureExample3 {

    public static void main(String[] args) throws Exception {
        // Generate ECDSA key pair
        KeyPair keyPair = generateECDSAKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Message to be signed
        String message = "Hello, this is a test message!";

        // Sign the message
        byte[] signature = signMessage(message, privateKey);

        // Verify the signature
        boolean isVerified = verifySignature(message, signature, publicKey);

        System.out.println("Signature verification result: " + isVerified);
    }

    private static KeyPair generateECDSAKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        SecureRandom secureRandom = new SecureRandom();
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
        keyPairGenerator.initialize(ecGenParameterSpec, secureRandom);
        return keyPairGenerator.generateKeyPair();
    }

    private static byte[] signMessage(String message, PrivateKey privateKey) throws Exception {
        Signature ecdsaSign = Signature.getInstance("SHA256withECDSA");
        ecdsaSign.initSign(privateKey);
        ecdsaSign.update(message.getBytes());
        return ecdsaSign.sign();
    }

    private static boolean verifySignature(String message, byte[] signature, PublicKey publicKey) throws Exception {
        Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA");
        ecdsaVerify.initVerify(publicKey);
        ecdsaVerify.update(message.getBytes());
        return ecdsaVerify.verify(signature);
    }
}