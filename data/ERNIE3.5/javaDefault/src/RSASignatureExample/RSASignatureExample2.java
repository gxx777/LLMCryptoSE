import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class RSASignatureExample2 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public RSASignatureExample2() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public String sign(String message) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(this.privateKey);
        signature.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    public boolean verify(String message, String signature) throws Exception {
        Signature signatureObj = Signature.getInstance("SHA256withRSA");
        signatureObj.initVerify(this.publicKey);
        signatureObj.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return signatureObj.verify(signatureBytes);
    }

    public static void main(String[] args) {
        try {
            RSASignatureExample2 rsaSignatureExample = new RSASignatureExample2();
            String message = "Hello, RSA!";
            String signature = rsaSignatureExample.sign(message);
            System.out.println("Signature: " + signature);
            boolean isValid = rsaSignatureExample.verify(message, signature);
            System.out.println("Signature valid: " + isValid);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}