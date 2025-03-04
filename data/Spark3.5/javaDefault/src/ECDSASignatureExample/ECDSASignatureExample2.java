import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

public class ECDSASignatureExample2 {

    public static void main(String[] args) throws Exception {
        // Generate key pair
        KeyPair keyPair = generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Message to be signed
        String message = "Hello, this is a test message!";

        // Sign the message
        byte[] signature = signMessage(privateKey, message);

        // Verify the signature
        boolean isVerified = verifySignature(publicKey, message, signature);

        System.out.println("Signature verification result: " + isVerified);
    }

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        SecureRandom secureRandom = new SecureRandom();
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
        keyPairGenerator.initialize(ecGenParameterSpec, secureRandom);
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] signMessage(PrivateKey privateKey, String message) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        return signature.sign();
    }

    public static boolean verifySignature(PublicKey publicKey, String message, byte[] signature) throws Exception {
        Signature signatureInstance = Signature.getInstance("SHA256withECDSA");
        signatureInstance.initVerify(publicKey);
        signatureInstance.update(message.getBytes());
        return signatureInstance.verify(signature);
    }
}