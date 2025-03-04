import java.security.*;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class RSASignatureExample1 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    // 初始化RSA密钥对
    public RSASignatureExample1() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    // 使用私钥对消息进行签名
    public String sign(String message) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(this.privateKey);
        privateSignature.update(message.getBytes(UTF_8));
        byte[] signature = privateSignature.sign();
        return Base64.getEncoder().encodeToString(signature);
    }

    // 使用公钥验证签名
    public boolean verify(String message, String signature) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(this.publicKey);
        publicSignature.update(message.getBytes(UTF_8));
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return publicSignature.verify(signatureBytes);
    }

    public static void main(String[] args) {
        try {
            RSASignatureExample1 rsaExample = new RSASignatureExample1();
            String message = "This is a test message for RSA signature.";
            String signature = rsaExample.sign(message);
            System.out.println("Signature: " + signature);
            boolean isValid = rsaExample.verify(message, signature);
            System.out.println("Is signature valid? " + isValid);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}