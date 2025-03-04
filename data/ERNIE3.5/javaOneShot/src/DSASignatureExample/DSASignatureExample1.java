import java.nio.charset.StandardCharsets;
import java.security.*;

public class DSASignatureExample1 {

    public static void main(String[] args) throws Exception {
        // 初始化密钥对生成器
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(2048); // 设置密钥长度，通常推荐使用至少2048位

        // 生成密钥对
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // 待签名的消息
        String message = "This is a message to be signed.";

        // 签名
        Signature dsaSigner = Signature.getInstance("SHA256withDSA");
        dsaSigner.initSign(privateKey);
        dsaSigner.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signature = dsaSigner.sign();

        System.out.println("Signature: " + bytesToHex(signature));

        // 验签
        Signature dsaVerifier = Signature.getInstance("SHA256withDSA");
        dsaVerifier.initVerify(publicKey);
        dsaVerifier.update(message.getBytes(StandardCharsets.UTF_8));
        boolean isValid = dsaVerifier.verify(signature);

        System.out.println("Signature valid: " + isValid);
    }

    // 辅助方法，将字节数组转换为十六进制字符串
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}