import java.nio.charset.StandardCharsets;
import java.security.*;

public class DSASignatureExample4 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public DSASignatureExample4() throws NoSuchAlgorithmException {
        // 生成DSA密钥对
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(2048); // 使用2048位密钥长度
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    /**
     * 使用私钥对消息进行签名
     *
     * @param message 要签名的消息
     * @return 签名
     * @throws Exception 如果签名过程中发生错误
     */
    public byte[] sign(String message) throws Exception {
        Signature dsa = Signature.getInstance("SHA256withDSA"); // 使用SHA-256作为DSA的哈希函数
        dsa.initSign(privateKey);
        dsa.update(message.getBytes(StandardCharsets.UTF_8));
        return dsa.sign();
    }

    /**
     * 使用公钥验证消息的签名
     *
     * @param message  要验证的消息
     * @param signature 消息的签名
     * @return 如果签名有效则返回true，否则返回false
     * @throws Exception 如果验签过程中发生错误
     */
    public boolean verify(String message, byte[] signature) throws Exception {
        Signature dsa = Signature.getInstance("SHA256withDSA");
        dsa.initVerify(publicKey);
        dsa.update(message.getBytes(StandardCharsets.UTF_8));
        return dsa.verify(signature);
    }

    public static void main(String[] args) {
        try {
            // 创建DSASignatureExample4实例
            DSASignatureExample4 signer = new DSASignatureExample4();

            // 要签名的消息
            String message = "Hello, DSA!";

            // 对消息进行签名
            byte[] signature = signer.sign(message);

            // 验证签名
            boolean isValid = signer.verify(message, signature);
            System.out.println("Signature is valid: " + isValid);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}