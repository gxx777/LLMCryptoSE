import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class ECDSASignatureExample4 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public ECDSASignatureExample4() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256); // 使用256位密钥长度
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    /**
     * 使用私钥对消息进行签名
     *
     * @param message 要签名的消息
     * @return 签名的Base64编码字符串
     * @throws Exception 如果签名过程中发生错误
     */
    public String sign(String message) throws Exception {
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initSign(privateKey);
        ecdsa.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signature = ecdsa.sign();
        return Base64.getEncoder().encodeToString(signature);
    }

    /**
     * 使用公钥验证消息的签名
     *
     * @param message    要验证的消息
     * @param signature  签名的Base64编码字符串
     * @return 如果签名有效则返回true，否则返回false
     * @throws Exception 如果验签过程中发生错误
     */
    public boolean verify(String message, String signature) throws Exception {
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initVerify(publicKey);
        ecdsa.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] sigBytes = Base64.getDecoder().decode(signature);
        return ecdsa.verify(sigBytes);
    }

    public static void main(String[] args) {
        try {
            ECDSASignatureExample4 example = new ECDSASignatureExample4();
            String message = "Hello, ECDSA!";
            String signature = example.sign(message);
            System.out.println("Signature: " + signature);
            boolean isValid = example.verify(message, signature);
            System.out.println("Signature valid: " + isValid);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}