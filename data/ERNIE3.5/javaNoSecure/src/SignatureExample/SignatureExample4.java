import java.security.*;

import static java.nio.charset.StandardCharsets.UTF_8;

public class SignatureExample4 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    // 生成密钥对
    public void generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048); // 密钥长度
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    // 使用私钥对消息进行签名
    public byte[] sign(String message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(this.privateKey);
        privateSignature.update(message.getBytes(UTF_8));
        return privateSignature.sign();
    }

    // 使用公钥验证签名
    public boolean verify(String message, byte[] signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(this.publicKey);
        publicSignature.update(message.getBytes(UTF_8));
        return publicSignature.verify(signature);
    }

    public static void main(String[] args) {
        try {
            SignatureExample4 signer = new SignatureExample4();
            signer.generateKeyPair(); // 生成密钥对

            String message = "Hello, this is a message to be signed!";

            // 签名
            byte[] signature = signer.sign(message);
            System.out.println("Signature generated: " + bytesToHex(signature));

            // 验签
            boolean isValid = signer.verify(message, signature);
            System.out.println("Signature is valid: " + isValid);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // 辅助方法：将字节转换为十六进制字符串
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}