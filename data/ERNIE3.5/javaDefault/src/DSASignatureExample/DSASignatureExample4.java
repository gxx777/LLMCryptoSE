import java.nio.charset.StandardCharsets;
import java.security.*;

public class DSASignatureExample4 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public DSASignatureExample4(PrivateKey privateKey, PublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    /**
     * 使用DSA算法对消息进行签名
     *
     * @param message 要签名的消息
     * @return 签名
     * @throws Exception 如果签名过程中发生错误
     */
    public byte[] sign(String message) throws Exception {
        Signature dsa = Signature.getInstance("SHA256withDSA");
        dsa.initSign(privateKey);
        dsa.update(message.getBytes(StandardCharsets.UTF_8));
        return dsa.sign();
    }

    /**
     * 使用DSA算法验证签名
     *
     * @param message  要验证的消息
     * @param signature 签名
     * @return 如果签名有效则返回true，否则返回false
     * @throws Exception 如果验证过程中发生错误
     */
    public boolean verify(String message, byte[] signature) throws Exception {
        Signature dsa = Signature.getInstance("SHA256withDSA");
        dsa.initVerify(publicKey);
        dsa.update(message.getBytes(StandardCharsets.UTF_8));
        return dsa.verify(signature);
    }

    /**
     * 生成DSA密钥对
     *
     * @return DSA密钥对
     * @throws NoSuchAlgorithmException 如果DSA密钥对生成过程中发生错误
     */
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(2048); // 使用2048位密钥长度
        return keyPairGenerator.generateKeyPair();
    }

    public static void main(String[] args) {
        try {
            // 生成DSA密钥对
            KeyPair keyPair = generateKeyPair();

            // 创建DSASignatureExample4实例
            DSASignatureExample4 example = new DSASignatureExample4(keyPair.getPrivate(), keyPair.getPublic());

            // 要签名的消息
            String message = "Hello, DSA!";

            // 对消息进行签名
            byte[] signature = example.sign(message);

            // 验证签名
            boolean isValid = example.verify(message, signature);

            System.out.println("Signature valid: " + isValid);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}