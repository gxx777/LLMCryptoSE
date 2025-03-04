import java.security.*;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class RSASignatureExample2 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public RSASignatureExample2() throws NoSuchAlgorithmException {
        // 生成RSA密钥对
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    /**
     * 使用私钥对消息进行签名
     *
     * @param message 要签名的消息
     * @return 签名
     * @throws Exception 签名过程中可能出现的异常
     */
    public String sign(String message) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(this.privateKey);
        privateSignature.update(message.getBytes(UTF_8));
        byte[] signature = privateSignature.sign();
        return Base64.getEncoder().encodeToString(signature);
    }

    /**
     * 使用公钥验证消息的签名
     *
     * @param message   要验证的消息
     * @param signature 消息的签名
     * @return 如果签名有效，返回true；否则返回false
     * @throws Exception 验签过程中可能出现的异常
     */
    public boolean verify(String message, String signature) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(this.publicKey);
        publicSignature.update(message.getBytes(UTF_8));
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return publicSignature.verify(signatureBytes);
    }

    public static void main(String[] args) {
        try {
            RSASignatureExample2 rsaExample = new RSASignatureExample2();

            // 签名
            String message = "Hello, RSA!";
            String signature = rsaExample.sign(message);
            System.out.println("Signature: " + signature);

            // 验签
            boolean isValid = rsaExample.verify(message, signature);
            System.out.println("Is signature valid? " + isValid);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}