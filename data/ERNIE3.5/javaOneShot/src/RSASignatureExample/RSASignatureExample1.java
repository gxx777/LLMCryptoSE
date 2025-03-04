import java.security.*;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class RSASignatureExample1 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public RSASignatureExample1() throws NoSuchAlgorithmException {
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
    public String signMessage(String message) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(this.privateKey);
        privateSignature.update(message.getBytes(UTF_8));
        byte[] signature = privateSignature.sign();
        return Base64.getEncoder().encodeToString(signature);
    }

    /**
     * 使用公钥验证消息的签名
     *
     * @param message   被签名的消息
     * @param signature 签名的Base64编码字符串
     * @return 如果签名有效则返回true，否则返回false
     * @throws Exception 如果验签过程中发生错误
     */
    public boolean verifySignature(String message, String signature) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(this.publicKey);
        publicSignature.update(message.getBytes(UTF_8));
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return publicSignature.verify(signatureBytes);
    }

    public static void main(String[] args) {
        try {
            RSASignatureExample1 example = new RSASignatureExample1();
            String message = "Hello, RSA!";
            String signature = example.signMessage(message);
            System.out.println("Signature: " + signature);
            boolean isValid = example.verifySignature(message, signature);
            System.out.println("Signature valid: " + isValid);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}