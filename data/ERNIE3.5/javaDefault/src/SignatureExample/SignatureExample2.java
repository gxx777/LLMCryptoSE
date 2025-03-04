import java.security.*;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class SignatureExample2 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public SignatureExample2() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    public String sign(String message) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA", "BC");
        signature.initSign(privateKey);
        signature.update(message.getBytes(UTF_8));
        byte[] signatureBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    public boolean verify(String message, String signature) throws Exception {
        Signature signatureToVerify = Signature.getInstance("SHA256withRSA", "BC");
        signatureToVerify.initVerify(publicKey);
        signatureToVerify.update(message.getBytes(UTF_8));
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return signatureToVerify.verify(signatureBytes);
    }

    public static void main(String[] args) {
        try {
            SignatureExample2 example = new SignatureExample2();
            String message = "Hello, World!";
            String signature = example.sign(message);
            System.out.println("Signature: " + signature);
            boolean isValid = example.verify(message, signature);
            System.out.println("Signature Valid: " + isValid);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}