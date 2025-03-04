import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class SignatureExample4 {
    public static void main(String[] args) {
        try {
            // 生成RSA密钥对
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // 要签名的消息
            byte[] message = "This is a secret message".getBytes();

            // 使用私钥对消息进行签名
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(message);
            byte[] digitalSignature = signature.sign();

            System.out.println("Digital Signature: " + new String(digitalSignature));

            // 使用公钥对消息进行验签
            signature.initVerify(publicKey);
            signature.update(message);
            boolean verified = signature.verify(digitalSignature);

            System.out.println("Signature verified: " + verified);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}