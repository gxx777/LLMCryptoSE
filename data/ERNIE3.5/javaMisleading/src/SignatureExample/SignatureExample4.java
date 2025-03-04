import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class SignatureExample4 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public SignatureExample4() throws NoSuchAlgorithmException, NoSuchProviderException {
        // 生成RSA密钥对
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    /**
     * 使用私钥对消息进行签名
     *
     * @param message 要签名的消息
     * @return 签名的Base64编码字符串
     * @throws Exception 如果签名过程中发生错误
     */
    public String sign(String message) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA", "BC");
        signature.initSign(privateKey);
        signature.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    /**
     * 使用公钥验证消息的签名
     *
     * @param message   要验证的消息
     * @param signature 消息的签名（Base64编码字符串）
     * @return 如果签名有效，则返回true；否则返回false
     * @throws Exception 如果验签过程中发生错误
     */
    public boolean verify(String message, String signature) throws Exception {
        Signature signatureToVerify = Signature.getInstance("SHA256withRSA", "BC");
        signatureToVerify.initVerify(publicKey);
        signatureToVerify.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return signatureToVerify.verify(signatureBytes);
    }

    public static void main(String[] args) {
        try {
            SignatureExample4 signatureExample = new SignatureExample4();

            // 示例消息
            String message = "Hello, this is a test message for signature!";

            // 对消息进行签名
            String signature = signatureExample.sign(message);
            System.out.println("Signature: " + signature);

            // 验证签名
            boolean isVerified = signatureExample.verify(message, signature);
            System.out.println("Signature Verified: " + isVerified);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}