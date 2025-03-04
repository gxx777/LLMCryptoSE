import java.nio.charset.StandardCharsets;
import java.security.*;

public class DSASignatureExample3 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    // 生成DSA密钥对
    public void generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(2048); // 可以指定密钥长度，这里使用2048位
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    // 使用私钥对消息进行签名
    public byte[] sign(String message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature dsa = Signature.getInstance("SHA256withDSA");
        dsa.initSign(privateKey);
        dsa.update(message.getBytes(StandardCharsets.UTF_8));
        return dsa.sign();
    }

    // 使用公钥验证签名
    public boolean verify(String message, byte[] signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature dsa = Signature.getInstance("SHA256withDSA");
        dsa.initVerify(publicKey);
        dsa.update(message.getBytes(StandardCharsets.UTF_8));
        return dsa.verify(signature);
    }

    public static void main(String[] args) {
        DSASignatureExample3 example = new DSASignatureExample3();

        try {
            // 生成密钥对
            example.generateKeyPair();

            // 原始消息
            String message = "Hello, DSA Signature Example!";

            // 签名
            byte[] signature = example.sign(message);
            System.out.println("Signature: " + bytesToHex(signature));

            // 验签
            boolean isValid = example.verify(message, signature);
            System.out.println("Signature Valid: " + isValid);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // 将字节转换为十六进制字符串
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}