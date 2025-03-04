import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class RSASignatureExample4 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public RSASignatureExample4() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, new SecureRandom());
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    public String sign(String message) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    public boolean verify(String message, String signature) throws Exception {
        Signature signatureInstance = Signature.getInstance("SHA256withRSA");
        signatureInstance.initVerify(publicKey);
        signatureInstance.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return signatureInstance.verify(signatureBytes);
    }

    public static void main(String[] args) {
        try {
            RSASignatureExample4 rsaExample = new RSASignatureExample4();
            String message = "Hello, RSA!";
            String signature = rsaExample.sign(message);
            System.out.println("Signature: " + signature);
            boolean isValid = rsaExample.verify(message, signature);
            System.out.println("Signature valid: " + isValid);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}