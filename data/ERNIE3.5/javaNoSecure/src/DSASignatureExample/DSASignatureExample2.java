import java.nio.charset.StandardCharsets;
import java.security.*;

public class DSASignatureExample2 {

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
        Signature dsaSigner = Signature.getInstance("SHA256withDSA");
        dsaSigner.initSign(privateKey);
        dsaSigner.update(originalMessage.getBytes(StandardCharsets.UTF_8));
        byte[] signature = dsaSigner.sign();

        // 验签
        Signature dsaVerifier = Signature.getInstance("SHA256withDSA");
        dsaVerifier.initVerify(publicKey);
        dsaVerifier.update(originalMessage.getBytes(StandardCharsets.UTF_8));
        boolean isVerified = dsaVerifier.verify(signature);

        System.out.println("Signature Verified: " + isVerified);
    }
}