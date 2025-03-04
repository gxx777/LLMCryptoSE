import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class SignatureExample2 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    // 初始化类时生成密钥对
    public SignatureExample2() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // 使用2048位密钥长度
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    // 使用私钥对消息进行签名
    public String signMessage(String message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(this.privateKey);
        privateSignature.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signature = privateSignature.sign();
        return Base64.getEncoder().encodeToString(signature);
    }

    // 使用公钥验证消息的签名
    public boolean verifySignature(String message, String signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(this.publicKey);
        publicSignature.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return publicSignature.verify(signatureBytes);
    }

    // 测试类
    public static void main(String[] args) {
        try {
            SignatureExample2 signer = new SignatureExample2();
            String message = "Hello, this is a test message!";

            // 签名消息
            String signature = signer.signMessage(message);
            System.out.println("Signature: " + signature);

            // 验证签名
            boolean isValid = signer.verifySignature(message, signature);
            System.out.println("Signature valid: " + isValid);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}