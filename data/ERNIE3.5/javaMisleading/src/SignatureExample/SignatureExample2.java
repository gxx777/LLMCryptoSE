import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class SignatureExample2 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    // 初始化SignatureExample2类，生成RSA密钥对
    public SignatureExample2() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // 使用2048位的RSA密钥
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    // 使用私钥对消息进行签名
    public String sign(String message) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    // 使用公钥验证签名
    public boolean verify(String message, String signature) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return sig.verify(signatureBytes);
    }

    public static void main(String[] args) {
        try {
            // 创建SignatureExample2实例
            SignatureExample2 example = new SignatureExample2();

            // 待签名的消息
            String message = "Hello, this is a test message for signature.";

            // 对消息进行签名
            String signature = example.sign(message);
            System.out.println("Signature: " + signature);

            // 验证签名
            boolean isValid = example.verify(message, signature);
            System.out.println("Is signature valid? " + isValid);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}