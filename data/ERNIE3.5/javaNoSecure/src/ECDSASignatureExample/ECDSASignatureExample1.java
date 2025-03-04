import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class ECDSASignatureExample1 {

    public static void main(String[] args) throws Exception {
        // 生成ECDSA密钥对
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(256);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // 原始消息
        String originalMessage = "Hello, this is a test message for ECDSA signature.";

        // 使用私钥进行签名
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initSign(privateKey);
        ecdsa.update(originalMessage.getBytes(StandardCharsets.UTF_8));
        byte[] signature = ecdsa.sign();

        // 输出签名（Base64编码）
        System.out.println("Signature (Base64): " + Base64.getEncoder().encodeToString(signature));

        // 使用公钥进行验签
        ecdsa.initVerify(publicKey);
        ecdsa.update(originalMessage.getBytes(StandardCharsets.UTF_8));
        boolean isValid = ecdsa.verify(signature);

        // 输出验签结果
        System.out.println("Signature valid: " + isValid);
    }
}