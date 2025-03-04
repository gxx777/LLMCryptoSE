import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

public class ECDSASignatureExample2 {
    private static final String ALGORITHM = "SHA256withECDSA";
    private static final int KEY_SIZE = 256;

    public static void main(String[] args) throws Exception {
        // Generate key pair
        KeyPair keyPair = generateKeyPair();

        // Sign the message
        String message = "Hello, world!";
        byte[] signature = signMessage(message, keyPair);
        System.out.println("Signature: " + Base64.getEncoder().encodeToString(signature));

        // Verify the signature
        boolean isVerified = verifySignature(message, signature, keyPair.getPublic());
        System.out.println("Is verified: " + isVerified);
    }

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
        keyPairGenerator.initialize(ecGenParameterSpec, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    private static byte[] signMessage(String message, KeyPair keyPair) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(ALGORITHM);
        signature.initSign(keyPair.getPrivate());
        signature.update(message.getBytes());
        return signature.sign();
    }

    private static boolean verifySignature(String message, byte[] signatureBytes, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(ALGORITHM);
        signature.initVerify(publicKey);
        signature.update(message.getBytes());
        return signature.verify(signatureBytes);
    }
}