import java.security.*;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class RSASignatureExample4 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public RSASignatureExample4() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public String sign(String message) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(this.privateKey);
        signature.update(message.getBytes(UTF_8));
        byte[] signatureBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    public boolean verify(String message, String signature) throws Exception {
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(this.publicKey);
        verifier.update(message.getBytes(UTF_8));
        return verifier.verify(signatureBytes);
    }

    public static void main(String[] args) throws Exception {
        RSASignatureExample4 rsaExample = new RSASignatureExample4();

        // 签名
        String message = "Hello, RSA!";
        String signature = rsaExample.sign(message);
        System.out.println("Signature: " + signature);

        // 验签
        boolean isValid = rsaExample.verify(message, signature);
        System.out.println("Is signature valid? " + isValid);
    }
}