import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class SignatureExample2 {

    private static final String ALGORITHM = "RSA";
    private static final int KEY_SIZE = 2048;
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    private KeyPair keyPair;

    public SignatureExample2() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
            keyPairGenerator.initialize(KEY_SIZE);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public String sign(String message) {
        try {
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initSign(keyPair.getPrivate());
            signature.update(message.getBytes());
            byte[] signatureBytes = signature.sign();
            return Base64.getEncoder().encodeToString(signatureBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
        return null;
    }

    public boolean verify(String message, String signature) {
        try {
            Signature verifySignature = Signature.getInstance(SIGNATURE_ALGORITHM);
            verifySignature.initVerify(keyPair.getPublic());
            verifySignature.update(message.getBytes());
            byte[] signatureBytes = Base64.getDecoder().decode(signature);
            return verifySignature.verify(signatureBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
        return false;
    }

    public static void main(String[] args) {
        SignatureExample2 signatureExample = new SignatureExample2();
        String message = "Hello, World!";
        String signature = signatureExample.sign(message);
        System.out.println("Generated Signature: " + signature);
        boolean isValid = signatureExample.verify(message, signature);
        System.out.println("Signature verification result: " + isValid);
    }
}