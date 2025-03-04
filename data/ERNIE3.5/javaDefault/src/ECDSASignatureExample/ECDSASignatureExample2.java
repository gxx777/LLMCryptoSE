import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class ECDSASignatureExample2 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public ECDSASignatureExample2() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", "BC"); // 使用Bouncy Castle作为提供者
        keyGen.initialize(new ECGenParameterSpec("secp256r1")); // 使用secp256r1曲线
        KeyPair keyPair = keyGen.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    /**
     * 使用私钥对消息进行签名
     *
     * @param message 要签名的消息
     * @return 签名
     * @throws Exception 如果签名过程中发生错误
     */
    public byte[] sign(String message) throws Exception {
        Signature ecdsa = Signature.getInstance("SHA256withECDSA", "BC"); // 使用Bouncy Castle作为提供者，并使用SHA-256作为消息摘要算法
        ecdsa.initSign(this.privateKey);
        ecdsa.update(message.getBytes(StandardCharsets.UTF_8));
        return ecdsa.sign();
    }

    /**
     * 使用公钥验证消息的签名
     *
     * @param message  要验证的消息
     * @param signature 消息的签名
     * @return 如果签名有效，返回true；否则返回false
     * @throws Exception 如果验签过程中发生错误
     */
    public boolean verify(String message, byte[] signature) throws Exception {
        Signature ecdsa = Signature.getInstance("SHA256withECDSA", "BC"); // 使用Bouncy Castle作为提供者，并使用SHA-256作为消息摘要算法
        ecdsa.initVerify(this.publicKey);
        ecdsa.update(message.getBytes(StandardCharsets.UTF_8));
        return ecdsa.verify(signature);
    }

    public static void main(String[] args) {
        try {
            ECDSASignatureExample2 ecdsaExample = new ECDSASignatureExample2();
            String message = "Hello, ECDSA!";

            // 签名
            byte[] signature = ecdsaExample.sign(message);
            System.out.println("Signature: " + bytesToHex(signature));

            // 验签
            boolean isValid = ecdsaExample.verify(message, signature);
            System.out.println("Signature valid: " + isValid);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // 将字节数组转换为十六进制字符串的辅助方法
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}