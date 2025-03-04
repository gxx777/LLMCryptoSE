import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class DSASignatureExample2 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public DSASignatureExample2() throws NoSuchAlgorithmException {
        // 创建DSA密钥对生成器
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        // 初始化密钥对生成器
        keyGen.initialize(2048);
        // 生成密钥对
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    /**
     * 使用私钥对消息进行签名
     *
     * @param message 要签名的消息
     * @return 签名结果，以Base64编码的字符串形式返回
     * @throws Exception 签名过程中可能抛出的异常
     */
    public String sign(String message) throws Exception {
        Signature dsa = Signature.getInstance("SHA256withDSA");
        dsa.initSign(this.privateKey);
        dsa.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signature = dsa.sign();
        return Base64.getEncoder().encodeToString(signature);
    }

    /**
     * 使用公钥验证消息的签名
     *
     * @param message   要验证的消息
     * @param signature 消息的签名，Base64编码的字符串形式
     * @return 验证结果，true表示签名有效，false表示签名无效
     * @throws Exception 验证过程中可能抛出的异常
     */
    public boolean verify(String message, String signature) throws Exception {
        Signature dsa = Signature.getInstance("SHA256withDSA");
        dsa.initVerify(this.publicKey);
        dsa.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] sigBytes = Base64.getDecoder().decode(signature);
        return dsa.verify(sigBytes);
    }

    public static void main(String[] args) {
        try {
            DSASignatureExample2 dsaExample = new DSASignatureExample2();
            String message = "Hello, DSA!";

            // 签名
            String signature = dsaExample.sign(message);
            System.out.println("Signature: " + signature);

            // 验签
            boolean isValid = dsaExample.verify(message, signature);
            System.out.println("Signature valid: " + isValid);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}