import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class ECDSASignatureExample3 {

    // 生成ECDSA密钥对
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(256); // 使用256位密钥长度
        return keyPairGenerator.generateKeyPair();
    }

    // 使用私钥签名消息
    public static byte[] signMessage(byte[] message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(message);
        return signature.sign();
    }

    // 使用公钥验签消息
    public static boolean verifySignature(byte[] message, byte[] signature, PublicKey publicKey) throws Exception {
        Signature signatureInstance = Signature.getInstance("SHA256withECDSA");
        signatureInstance.initVerify(publicKey);
        signatureInstance.update(message);
        return signatureInstance.verify(signature);
    }

    // 主函数，演示用法
    public static void main(String[] args) throws Exception {
        // 生成密钥对
        KeyPair keyPair = generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // 待签名的消息
        String message = "Hello, this is a test message for ECDSA signature.";
        byte[] messageBytes = message.getBytes();

        // 签名消息
        byte[] signature = signMessage(messageBytes, privateKey);

        // 验证签名
        boolean isValid = verifySignature(messageBytes, signature, publicKey);
        System.out.println("Signature is valid: " + isValid);
    }
}