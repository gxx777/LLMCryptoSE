import java.security.*;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class DSASignatureExample2 {

    // 用于签名的私钥
    private PrivateKey privateKey;

    // 用于验签的公钥
    private PublicKey publicKey;

    // 初始化DSASignatureExample2，生成密钥对
    public DSASignatureExample2() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        keyGen.initialize(2048); // 设置密钥长度，可根据需要调整
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    // 使用私钥对消息进行签名
    public String sign(String message) throws Exception {
        Signature dsa = Signature.getInstance("SHA256withDSA");
        dsa.initSign(this.privateKey);
        dsa.update(message.getBytes(UTF_8));
        byte[] realSig = dsa.sign();
        return Base64.getEncoder().encodeToString(realSig);
    }

    // 使用公钥对签名进行验签
    public boolean verify(String message, String signature) throws Exception {
        Signature dsa = Signature.getInstance("SHA256withDSA");
        dsa.initVerify(this.publicKey);
        dsa.update(message.getBytes(UTF_8));
        byte[] sigBytes = Base64.getDecoder().decode(signature);
        return dsa.verify(sigBytes);
    }

    public static void main(String[] args) {
        try {
            DSASignatureExample2 dsaExample = new DSASignatureExample2();

            // 消息
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