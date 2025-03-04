import java.security.*;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class SignatureExample3 {

    public static void main(String[] args) throws Exception {
        // 生成RSA密钥对
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // 原始消息
        String originalMessage = "Hello, World!";

        // 使用私钥对消息进行签名
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(originalMessage.getBytes(UTF_8));
        byte[] signature = privateSignature.sign();

        // 将签名转换为Base64编码的字符串
        String signedMessage = Base64.getEncoder().encodeToString(signature);

        // 使用公钥验证签名
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(originalMessage.getBytes(UTF_8));
        boolean isValid = publicSignature.verify(signature);

        System.out.println("Signed Message (Base64): " + signedMessage);
        System.out.println("Is Signature Valid? " + isValid);
    }
}