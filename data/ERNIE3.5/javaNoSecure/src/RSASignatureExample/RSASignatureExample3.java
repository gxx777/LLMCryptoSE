import java.security.*;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class RSASignatureExample3 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public RSASignatureExample3() throws NoSuchAlgorithmException {
        // 生成RSA密钥对
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    /**
     * 使用私钥对消息进行签名
     * @param message 需要签名的消息
     * @return 签名结果，以Base64编码的字符串形式返回
     * @throws Exception 签名过程中可能抛出的异常
     */
    public String sign(String message) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(this.privateKey);
        signature.update(message.getBytes(UTF_8));
        byte[] signatureBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    /**
     * 使用公钥验证签名
     * @param message 原始消息
     * @param signature 需要验证的签名，以Base64编码的字符串形式提供
     * @return 如果签名有效，则返回true；否则返回false
     * @throws Exception 验证过程中可能抛出的异常
     */
    public boolean verify(String message, String signature) throws Exception {
        Signature signatureToVerify = Signature.getInstance("SHA256withRSA");
        signatureToVerify.initVerify(this.publicKey);
        signatureToVerify.update(message.getBytes(UTF_8));
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return signatureToVerify.verify(signatureBytes);
    }

    public static void main(String[] args) {
        try {
            RSASignatureExample3 rsaExample = new RSASignatureExample3();

            // 测试签名功能
            String message = "Hello, RSA!";
            String signature = rsaExample.sign(message);
            System.out.println("Signature: " + signature);

            // 测试验签功能
            boolean isValid = rsaExample.verify(message, signature);
            System.out.println("Is signature valid? " + isValid);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}