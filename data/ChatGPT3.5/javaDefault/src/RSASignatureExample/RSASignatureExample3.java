import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

public class RSASignatureExample3 {

    private static final String ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    public static void main(String[] args) {
        try {
            // Generate key pair
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Get private and public keys
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            // Message to be signed
            String message = "This is a secret message";

            // Sign the message
            byte[] signature = sign(message, privateKey);

            System.out.println("Signature: " + Base64.getEncoder().encodeToString(signature));

            // Verify the signature
            boolean verified = verify(message, signature, publicKey);

            System.out.println("Signature verified: " + verified);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static byte[] sign(String message, PrivateKey privateKey) throws Exception {
        Signature rsa = Signature.getInstance(SIGNATURE_ALGORITHM);
        rsa.initSign(privateKey);
        rsa.update(message.getBytes());
        return rsa.sign();
    }

    public static boolean verify(String message, byte[] signature, PublicKey publicKey) throws Exception {
        Signature rsa = Signature.getInstance(SIGNATURE_ALGORITHM);
        rsa.initVerify(publicKey);
        rsa.update(message.getBytes());
        return rsa.verify(signature);
    }

}