import java.security.*;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class SignatureExample2 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public SignatureExample2() throws NoSuchAlgorithmException {
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
     * @return 签名
     * @throws Exception 如果签名过程中发生错误
     */
    public String sign(String message) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(this.privateKey);
        privateSignature.update(message.getBytes(UTF_8));
        byte[] signature = privateSignature.sign();
        return Base64.getEncoder().encodeToString(signature);
    }

    /**
     * 使用公钥验证签名
     *
     * @param message    原始消息
     * @param signature  签名
     * @return 是否签名有效
     * @throws Exception 如果验证过程中发生错误
     */
    public boolean verify(String message, String signature) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(this.publicKey);
        publicSignature.update(message.getBytes(UTF_8));
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return publicSignature.verify(signatureBytes);
    }

    public static void main(String[] args) {
        try {
            SignatureExample2 example = new SignatureExample2();
            String message = "Hello, this is a test message!";
            String signature = example.sign(message);
            System.out.println("Signature: " + signature);

            boolean isValid = example.verify(message, signature);
            System.out.println("Signature valid: " + isValid);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}