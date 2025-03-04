import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

public class ECDSASignatureExample4 {
    private static final String ALGORITHM = "SHA256withECDSA";
    private static final int KEY_SIZE = 256;

    public static void main(String[] args) throws Exception {
        // Generate key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
        keyPairGenerator.initialize(ecGenParameterSpec, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Sign the message
        String message = "Hello, world!";
        byte[] signature = signMessage(message, privateKey);

        // Verify the signature
        boolean isVerified = verifySignature(message, signature, publicKey);
        System.out.println("Signature verification result: " + isVerified);
    }

    public static byte[] signMessage(String message, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(ALGORITHM);
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        return signature.sign();
    }

    public static boolean verifySignature(String message, byte[] signatureBytes, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(ALGORITHM);
        signature.initVerify(publicKey);
        signature.update(message.getBytes());
        return signature.verify(signatureBytes);
    }
}