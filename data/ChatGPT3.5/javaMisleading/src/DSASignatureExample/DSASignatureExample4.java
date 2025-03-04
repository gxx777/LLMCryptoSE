import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class DSASignatureExample4 {

    public static void main(String[] args) {
        try {
            // 生成密钥对
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
            keyPairGenerator.initialize(1024);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // 获取私钥和公钥
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            // 要签名的消息
            String message = "Hello, world!";

            // 使用私钥对消息进行签名
            Signature signature = Signature.getInstance("SHA256withDSA");
            signature.initSign(privateKey);
            signature.update(message.getBytes());
            byte[] signatureBytes = signature.sign();

            // 将签名转换为Base64格式
            String signatureBase64 = Base64.getEncoder().encodeToString(signatureBytes);
            System.out.println("Signature: " + signatureBase64);

            // 使用公钥对签名进行验证
            signature.initVerify(publicKey);
            signature.update(message.getBytes());
            boolean verified = signature.verify(signatureBytes);

            if (verified) {
                System.out.println("Signature verified successfully!");
            } else {
                System.out.println("Signature verification failed!");
            }
        } catch (Exception e) {
            System.err.println("An error occurred: " + e.getMessage());
            e.printStackTrace();
        }
    }
}