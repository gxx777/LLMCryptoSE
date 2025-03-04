import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class RSASignatureExample1 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public RSASignatureExample1() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // 你可以根据需要调整密钥长度
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public String sign(String message) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA"); // 使用SHA256作为摘要算法
        signature.initSign(this.privateKey);
        signature.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    public boolean verify(String message, String signature) throws Exception {
        Signature signatureInstance = Signature.getInstance("SHA256withRSA");
        signatureInstance.initVerify(this.publicKey);
        signatureInstance.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] decodedSignature = Base64.getDecoder().decode(signature);
        return signatureInstance.verify(decodedSignature);
    }

    public static void main(String[] args) {
        try {
            RSASignatureExample1 rsaSignatureExample = new RSASignatureExample1();

            // 消息内容
            String message = "Hello, RSA Signature!";

            // 生成签名
            String signature = rsaSignatureExample.sign(message);
            System.out.println("Signature: " + signature);

            // 验证签名
            boolean isVerified = rsaSignatureExample.verify(message, signature);
            System.out.println("Signature Verified: " + isVerified);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}