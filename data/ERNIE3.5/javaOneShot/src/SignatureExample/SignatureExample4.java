import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class SignatureExample4 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public SignatureExample4() throws NoSuchAlgorithmException {
        // 生成密钥对
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
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
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(this.privateKey);
        privateSignature.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signature = privateSignature.sign();
        return Base64.getEncoder().encodeToString(signature);
    }

    /**
     * 使用公钥验证消息的签名
     *
     * @param message  要验证的消息
     * @param signature 消息的签名（Base64编码字符串）
     * @return 如果签名有效，则返回true；否则返回false
     * @throws Exception 如果验签过程中发生错误
     */
    public boolean verify(String message, String signature) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(this.publicKey);
        publicSignature.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return publicSignature.verify(signatureBytes);
    }

    public static void main(String[] args) {
        try {
            SignatureExample4 signer = new SignatureExample4();
            String message = "Hello, World!";
            String signature = signer.sign(message);
            System.out.println("Signature: " + signature);
            boolean isValid = signer.verify(message, signature);
            System.out.println("Is signature valid? " + isValid);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}