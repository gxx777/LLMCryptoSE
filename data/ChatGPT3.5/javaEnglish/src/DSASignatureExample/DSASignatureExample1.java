import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;

public class DSASignatureExample1 {

    public static void main(String[] args) throws Exception {
        String message = "This is a secret message to be signed";

        // Generating DSA key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Signing the message
        Signature signature = Signature.getInstance("SHA256withDSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        byte[] signedMessage = signature.sign();

        System.out.println("Signed message: " + Arrays.toString(signedMessage));

        // Verifying the message
        Signature verifySignature = Signature.getInstance("SHA256withDSA");
        verifySignature.initVerify(publicKey);
        verifySignature.update(message.getBytes());

        boolean isVerified = verifySignature.verify(signedMessage);
        System.out.println("Is message verified: " + isVerified);
    }
}