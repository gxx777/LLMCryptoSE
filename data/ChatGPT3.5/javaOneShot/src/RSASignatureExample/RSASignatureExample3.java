import java.security.*;
import java.util.Base64;

public class RSASignatureExample3 {

    private static final String ALGORITHM = "RSA";

    // Generate key pair
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(2048); // Key length should be at least 2048 bits for security
        return keyPairGenerator.generateKeyPair();
    }

    // Sign the message using private key
    public static byte[] signMessage(String message, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        return signature.sign();
    }

    // Verify the signature using public key
    public static boolean verifySignature(String message, byte[] signatureToVerify, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(message.getBytes());
        return signature.verify(signatureToVerify);
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // Generate key pair
        KeyPair keyPair = generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        
        // Message to be signed
        String message = "Hello, world!";
        
        // Sign the message with private key
        byte[] signature = signMessage(message, privateKey);
        
        // Verify the signature with public key
        boolean isVerified = verifySignature(message, signature, publicKey);
        System.out.println("Signature verified: " + isVerified);
    }
}