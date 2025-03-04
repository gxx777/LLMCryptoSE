import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class DSASignatureExample1 {

    public static void main(String[] args) throws Exception {
        // 生成DSA密钥对
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // 原始消息
        String originalMessage = "Hello, DSA Signature!";

        // 签名
        Signature dsa = Signature.getInstance("SHA256withDSA");
        dsa.initSign(privateKey);
        dsa.update(originalMessage.getBytes(StandardCharsets.UTF_8));
        byte[] signature = dsa.sign();
        String signatureBase64 = Base64.getEncoder().encodeToString(signature);
        System.out.println("Signature (Base64): " + signatureBase64);

        // 验签
        dsa.initVerify(publicKey);
        dsa.update(originalMessage.getBytes(StandardCharsets.UTF_8));
        boolean isVerified = dsa.verify(signature);
        System.out.println("Signature Verified: " + isVerified);
    }
}