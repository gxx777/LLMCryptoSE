import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class ECDSASignatureExample2 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public ECDSASignatureExample2() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    /**
     * 使用私钥对消息进行签名
     *
     * @param message 要签名的消息
     * @return 签名结果，Base64编码的字符串
     * @throws Exception 签名过程中出现的异常
     */
    public String sign(String message) throws Exception {
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initSign(this.privateKey);
        ecdsa.update(message.getBytes(UTF_8));
        byte[] signature = ecdsa.sign();
        return Base64.getEncoder().encodeToString(signature);
    }

    /**
     * 使用公钥对签名进行验证
     *
     * @param message  原始消息
     * @param signature 签名结果，Base64编码的字符串
     * @return 验证结果，true表示验证成功，false表示验证失败
     * @throws Exception 验证过程中出现的异常
     */
    public boolean verify(String message, String signature) throws Exception {
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initVerify(this.publicKey);
        ecdsa.update(message.getBytes(UTF_8));
        byte[] sigBytes = Base64.getDecoder().decode(signature);
        return ecdsa.verify(sigBytes);
    }

    public static void main(String[] args) throws Exception {
        ECDSASignatureExample2 example = new ECDSASignatureExample2();

        // 原始消息
        String message = "Hello, ECDSA!";

        // 签名
        String signature = example.sign(message);
        System.out.println("Signature: " + signature);

        // 验签
        boolean isValid = example.verify(message, signature);
        System.out.println("Signature is valid: " + isValid);
    }
}