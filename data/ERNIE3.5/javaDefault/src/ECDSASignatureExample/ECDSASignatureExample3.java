import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

public class ECDSASignatureExample3 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    // 初始化密钥对
    public void initKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1")); // 使用secp256r1椭圆曲线
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    // 使用私钥对消息进行签名
    public String sign(String message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initSign(this.privateKey);
        ecdsa.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signature = ecdsa.sign();
        return Base64.getEncoder().encodeToString(signature);
    }

    // 使用公钥验证签名
    public boolean verify(String message, String signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initVerify(this.publicKey);
        ecdsa.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] sigBytes = Base64.getDecoder().decode(signature);
        return ecdsa.verify(sigBytes);
    }

    public static void main(String[] args) {
        try {
            ECDSASignatureExample3 example = new ECDSASignatureExample3();
            example.initKeyPair(); // 初始化密钥对

            String message = "Hello, ECDSA!";
            String signature = example.sign(message); // 对消息签名
            System.out.println("Signature: " + signature);

            boolean isValid = example.verify(message, signature); // 验证签名
            System.out.println("Signature valid: " + isValid);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}