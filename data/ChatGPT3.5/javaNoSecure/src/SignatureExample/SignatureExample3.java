import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

public class SignatureExample3 {

    private PublicKey publicKey;
    private PrivateKey privateKey;

    public SignatureExample3() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String signMessage(String message) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(message.getBytes());
            byte[] signatureBytes = signature.sign();
            return Base64.getEncoder().encodeToString(signatureBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public boolean verifySignature(String message, String signature) {
        try {
            Signature verifySignature = Signature.getInstance("SHA256withRSA");
            verifySignature.initVerify(publicKey);
            verifySignature.update(message.getBytes());
            byte[] signatureBytes = Base64.getDecoder().decode(signature);
            return verifySignature.verify(signatureBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static void main(String[] args) {
        SignatureExample3 signatureExample = new SignatureExample3();
        String message = "Hello, World!";
        
        String signedMessage = signatureExample.signMessage(message);
        System.out.println("Signed message: " + signedMessage);

        boolean isVerified = signatureExample.verifySignature(message, signedMessage);
        System.out.println("Is signature verified: " + isVerified);
    }
}