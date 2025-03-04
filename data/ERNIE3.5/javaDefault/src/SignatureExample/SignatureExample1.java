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

        // 原始消息
        String message = "Hello, World!";

        // 签名
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes(UTF_8));
        byte[] signatureBytes = signature.sign();
        String signatureBase64 = Base64.getEncoder().encodeToString(signatureBytes);
        System.out.println("Signature: " + signatureBase64);

        // 验签
        signature.initVerify(publicKey);
        signature.update(message.getBytes(UTF_8));
        boolean isVerified = signature.verify(signatureBytes);
        System.out.println("Is Verified: " + isVerified);
    }

    private static final String UTF_8 = "UTF-8";
}