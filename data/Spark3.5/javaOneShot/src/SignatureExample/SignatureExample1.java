import java.security.*;
import java.util.Base64;

public class SignatureExample1 {
    public static void main(String[] args) throws Exception {
        // 生成密钥对
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // 要签名的消息
        String message = "Hello, this is a secure message!";

        // 使用私钥对消息进行签名
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        byte[] signedMessage = signature.sign();
        String signedMessageBase64 = Base64.getEncoder().encodeToString(signedMessage);
        System.out.println("Signed message: " + signedMessageBase64);

        // 使用公钥验证签名
        signature.initVerify(publicKey);
        signature.update(message.getBytes());
        boolean isVerified = signature.verify(signedMessage);
        System.out.println("Is the signature verified? " + isVerified);
    }
}