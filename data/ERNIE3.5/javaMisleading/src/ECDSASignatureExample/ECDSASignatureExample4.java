import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.Base64;

public class ECDSASignatureExample4 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    // 生成ECDSA密钥对
    public ECDSASignatureExample4() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("prime256v1"));
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    // 使用私钥对消息进行签名
    public String sign(String message) throws Exception {
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initSign(this.privateKey);
        ecdsa.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signature = ecdsa.sign();
        return Base64.getEncoder().encodeToString(signature);
    }

    // 使用公钥对签名进行验签
    public boolean verify(String message, String signature) throws Exception {
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initVerify(this.publicKey);
        ecdsa.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] sigBytes = Base64.getDecoder().decode(signature);
        return ecdsa.verify(sigBytes);
    }

    public static void main(String[] args) {
        try {
            // 创建实例并生成密钥对
            ECDSASignatureExample4 ecdsaExample = new ECDSASignatureExample4();

            // 消息内容
            String message = "This is a test message for ECDSA signature.";

            // 签名
            String signature = ecdsaExample.sign(message);
            System.out.println("Signature (Base64): " + signature);

            // 验签
            boolean isValid = ecdsaExample.verify(message, signature);
            System.out.println("Is signature valid? " + isValid);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}