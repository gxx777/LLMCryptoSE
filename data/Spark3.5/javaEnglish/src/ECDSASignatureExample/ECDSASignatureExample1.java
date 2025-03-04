import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

public class ECDSASignatureExample1 {
    public static void main(String[] args) throws Exception {
        // Generate ECDSA key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
        keyPairGenerator.initialize(ecGenParameterSpec, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Message to be signed
        String message = "Hello, this is a secure message!";

        // Sign the message using ECDSA algorithm
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        byte[] signedMessage = signature.sign();

        // Verify the signed message using ECDSA algorithm
        signature.initVerify(publicKey);
        signature.update(message.getBytes());
        boolean isVerified = signature.verify(signedMessage);

        System.out.println("Original Message: " + message);
        System.out.println("Signed Message: " + Arrays.toString(signedMessage));
        System.out.println("Verification Result: " + isVerified);
    }
}