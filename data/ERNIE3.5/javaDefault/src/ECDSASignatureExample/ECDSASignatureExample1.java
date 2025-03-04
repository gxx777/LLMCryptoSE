import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class ECDSASignatureExample1 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public ECDSASignatureExample1() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        // 使用内置的"EC"算法生成密钥对
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC"); // 使用Bouncy Castle提供者
        keyGen.initialize(new ECGenParameterSpec("prime256v1")); // 使用P-256曲线
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    /**
     * 使用私钥对消息进行签名
     *
     * @param message 要签名的消息
     * @return 签名
     * @throws Exception 如果签名失败
     */
    public byte[] sign(String message) throws Exception {
        Signature signer = Signature.getInstance("SHA256withECDSA", "BC"); // 使用SHA-256withECDSA算法和Bouncy Castle提供者
        signer.initSign(this.privateKey);
        signer.update(message.getBytes(StandardCharsets.UTF_8));
        return signer.sign();
    }

    /**
     * 使用公钥验证签名
     *
     * @param message   原始消息
     * @param signature 签名
     * @return 是否验证成功
     * @throws Exception 如果验证失败
     */
    public boolean verify(String message, byte[] signature) throws Exception {
        Signature verifier = Signature.getInstance("SHA256withECDSA", "BC"); // 使用SHA-256withECDSA算法和Bouncy Castle提供者
        verifier.initVerify(this.publicKey);
        verifier.update(message.getBytes(StandardCharsets.UTF_8));
        return verifier.verify(signature);
    }

    public static void main(String[] args) {
        try {
            // 创建示例并生成密钥对
            ECDSASignatureExample1 example = new ECDSASignatureExample1();

            // 要签名的消息
            String message = "Hello, ECDSA!";

            // 签名消息
            byte[] signature = example.sign(message);

            // 验证签名
            boolean isValid = example.verify(message, signature);
            System.out.println("Signature is valid: " + isValid);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}