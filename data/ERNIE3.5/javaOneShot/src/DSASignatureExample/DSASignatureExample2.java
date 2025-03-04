import java.nio.charset.StandardCharsets;
import java.security.*;

public class DSASignatureExample2 {

    // 用于签名的私钥
    private PrivateKey privateKey;
    // 用于验签的公钥
    private PublicKey publicKey;

    // 初始化DSA密钥对
    public DSASignatureExample2() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(2048); // 设置密钥长度，推荐至少2048位
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    // 使用私钥对消息进行签名
    public byte[] sign(String message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature dsaSignature = Signature.getInstance("SHA256withDSA"); // 使用SHA-256作为DSA的散列算法
        dsaSignature.initSign(privateKey);
        dsaSignature.update(message.getBytes(StandardCharsets.UTF_8));
        return dsaSignature.sign();
    }

    // 使用公钥验证消息的签名
    public boolean verify(String message, byte[] signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature dsaSignature = Signature.getInstance("SHA256withDSA");
        dsaSignature.initVerify(publicKey);
        dsaSignature.update(message.getBytes(StandardCharsets.UTF_8));
        return dsaSignature.verify(signature);
    }

    public static void main(String[] args) {
        try {
            DSASignatureExample2 dsaExample = new DSASignatureExample2();

            // 测试消息
            String message = "This is a test message for DSA signature.";

            // 对消息进行签名
            byte[] signature = dsaExample.sign(message);

            // 验证签名
            boolean isValid = dsaExample.verify(message, signature);
            System.out.println("Signature valid: " + isValid);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}