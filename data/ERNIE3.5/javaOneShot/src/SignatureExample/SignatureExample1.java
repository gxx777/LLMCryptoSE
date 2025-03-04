import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class SignatureExample1 {

    public static void main(String[] args) throws Exception {
        // 生成RSA密钥对
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // 要签名的消息
        String message = "Hello, this is a test message for signature!";

        // 签名
        Signature rsa = Signature.getInstance("SHA256withRSA");
        rsa.initSign(privateKey);
        rsa.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signature = rsa.sign();

        // 输出签名（Base64编码）
        System.out.println("Signature (Base64): " + Base64.getEncoder().encodeToString(signature));

        // 验签
        rsa.initVerify(publicKey);
        rsa.update(message.getBytes(StandardCharsets.UTF_8));
        boolean isVerified = rsa.verify(signature);

        // 输出验签结果
        System.out.println("Signature Verified: " + isVerified);
    }
}