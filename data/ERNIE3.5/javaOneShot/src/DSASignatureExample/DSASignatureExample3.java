import java.nio.charset.StandardCharsets;
import java.security.*;

public class DSASignatureExample3 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    // 生成DSA密钥对
    public void generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(2048); // 使用足够长的密钥长度
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    // 使用私钥对消息进行签名
    public byte[] sign(String message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature dsa = Signature.getInstance("SHA256withDSA"); // 使用SHA-256作为消息摘要算法
        dsa.initSign(this.privateKey);
        dsa.update(message.getBytes(StandardCharsets.UTF_8));
        return dsa.sign();
    }

    // 使用公钥验证签名
    public boolean verify(String message, byte[] signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature dsa = Signature.getInstance("SHA256withDSA");
        dsa.initVerify(this.publicKey);
        dsa.update(message.getBytes(StandardCharsets.UTF_8));
        return dsa.verify(signature);
    }

    public static void main(String[] args) {
        try {
            DSASignatureExample3 example = new DSASignatureExample3();
            example.generateKeyPair(); // 生成密钥对

            String message = "Hello, DSA!"; // 要签名的消息
            byte[] signature = example.sign(message); // 对消息进行签名

            boolean isValid = example.verify(message, signature); // 验证签名
            System.out.println("Signature is valid: " + isValid);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}