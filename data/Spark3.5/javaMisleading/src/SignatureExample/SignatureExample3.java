import java.security.*;
import java.util.Base64;

public class SignatureExample3 {
    public static void main(String[] args) {
        try {
            // 生成密钥对
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // 要签名的消息
            String message = "这是一个待签名的消息";

            // 使用私钥对消息进行签名
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(message.getBytes());
            byte[] signedMessage = signature.sign();
            String signedMessageBase64 = Base64.getEncoder().encodeToString(signedMessage);
            System.out.println("签名后的消息（Base64编码）： " + signedMessageBase64);

            // 使用公钥验证签名
            signature.initVerify(publicKey);
            signature.update(message.getBytes());
            boolean isVerified = signature.verify(signedMessage);
            System.out.println("验签结果： " + (isVerified ? "成功" : "失败"));

        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
    }
}