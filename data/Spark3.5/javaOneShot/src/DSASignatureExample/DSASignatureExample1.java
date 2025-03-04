import java.security.*;
import java.util.Base64;

public class DSASignatureExample1 {
    public static void main(String[] args) throws Exception {
        // 生成密钥对
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        keyGen.initialize(2048); // 使用2048位密钥长度
        KeyPair keyPair = keyGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // 要签名的消息
        String message = "Hello, this is a message to be signed!";

        // 使用私钥对消息进行签名
        Signature signature = Signature.getInstance("SHA256withDSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        byte[] signedMessage = signature.sign();

        // 将签名后的消息转换为Base64编码
        String signedMessageBase64 = Base64.getEncoder().encodeToString(signedMessage);
        System.out.println("Signed message (Base64): " + signedMessageBase64);

        // 使用公钥对签名后的消息进行验签
        signature.initVerify(publicKey);
        signature.update(message.getBytes());
        boolean isVerified = signature.verify(signedMessage);
        System.out.println("Verification result: " + isVerified);
    }
}