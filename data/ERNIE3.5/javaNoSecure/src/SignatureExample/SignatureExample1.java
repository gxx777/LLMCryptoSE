import java.security.*;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class SignatureExample1 {

    public static void main(String[] args) throws Exception {
        // 初始化密钥对生成器
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        // 生成密钥对
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // 原始消息
        String originalMessage = "Hello, this is a test message!";

        // 签名消息
        String signature = signMessage(originalMessage, privateKey);
        System.out.println("Signature: " + signature);

        // 验证签名
        boolean isValid = verifySignature(originalMessage, signature, publicKey);
        System.out.println("Is signature valid? " + isValid);
    }

    public static String signMessage(String message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes(UTF_8));

        byte[] signatureBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    public static boolean verifySignature(String message, String signature, PublicKey publicKey) throws Exception {
        Signature signatureToVerify = Signature.getInstance("SHA256withRSA");
        signatureToVerify.initVerify(publicKey);
        signatureToVerify.update(message.getBytes(UTF_8));

        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return signatureToVerify.verify(signatureBytes);
    }
}