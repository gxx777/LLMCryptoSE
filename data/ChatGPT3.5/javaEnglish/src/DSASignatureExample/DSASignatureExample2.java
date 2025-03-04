import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class DSASignatureExample2 {

    private static final String ALGORITHM = "DSA";
    private static final int KEY_SIZE = 1024;

    public static void main(String[] args) {
        try {
            // Generate DSA key pair
            KeyPair keyPair = generateDSAKeyPair();

            // Create a message to be signed
            String message = "Hello, world!";
            byte[] messageBytes = message.getBytes();

            // Sign the message
            byte[] signature = sign(messageBytes, keyPair.getPrivate());

            // Verify the signature
            boolean isValid = verify(messageBytes, signature, keyPair.getPublic());

            if (isValid) {
                System.out.println("Signature is valid.");
            } else {
                System.out.println("Signature is invalid.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static KeyPair generateDSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(KEY_SIZE);
        return keyPairGenerator.generateKeyPair();
    }

    private static byte[] sign(byte[] message, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(ALGORITHM);
        signature.initSign(privateKey);
        signature.update(message);
        return signature.sign();
    }

    private static boolean verify(byte[] message, byte[] signature, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sig = Signature.getInstance(ALGORITHM);
        sig.initVerify(publicKey);
        sig.update(message);
        return sig.verify(signature);
    }
}