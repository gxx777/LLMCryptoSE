import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class DSASignatureExample1 {

    public static void main(String[] args) throws Exception {
        // 生成密钥对
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // 要签名的消息
        String message = "这是一个待签名的消息";

        // 使用私钥对消息进行签名
        byte[] signatureBytes = signMessage(privateKey, message);

        // 使用公钥对签名进行验证
        boolean isVerified = verifySignature(publicKey, message, signatureBytes);

        System.out.println("签名验证结果： " + (isVerified ? "成功" : "失败"));
    }

    public static byte[] signMessage(PrivateKey privateKey, String message) throws Exception {
        Signature signature = Signature.getInstance("SHA256withDSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        return signature.sign();
    }

    public static boolean verifySignature(PublicKey publicKey, String message, byte[] signatureBytes) throws Exception {
        Signature signature = Signature.getInstance("SHA256withDSA");
        signature.initVerify(publicKey);
        signature.update(message.getBytes());
        return signature.verify(signatureBytes);
    }
}