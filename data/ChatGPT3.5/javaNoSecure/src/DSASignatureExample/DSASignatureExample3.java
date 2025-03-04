import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class DSASignatureExample3 {

    public static void main(String[] args) {
        try {
            // 生成DSA密钥对
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
            keyPairGenerator.initialize(1024);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            // 创建消息
            String message = "Hello, World!";
            byte[] messageBytes = message.getBytes();

            // 使用私钥对消息进行签名
            Signature signature = Signature.getInstance("SHA1withDSA");
            signature.initSign(privateKey);
            signature.update(messageBytes);
            byte[] signatureBytes = signature.sign();
            String signatureBase64 = Base64.getEncoder().encodeToString(signatureBytes);
            System.out.println("Signature: " + signatureBase64);

            // 使用公钥对签名进行验证
            signature.initVerify(publicKey);
            signature.update(messageBytes);
            boolean verified = signature.verify(signatureBytes);
            if (verified) {
                System.out.println("Signature verified successfully");
            } else {
                System.out.println("Signature verification failed");
            }

        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
    }
}