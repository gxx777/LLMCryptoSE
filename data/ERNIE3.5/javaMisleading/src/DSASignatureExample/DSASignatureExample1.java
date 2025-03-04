import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class DSASignatureExample1 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public DSASignatureExample1() throws NoSuchAlgorithmException, InvalidKeySpecException {
        // 生成DSA密钥对
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    /**
     * 使用私钥对消息进行签名
     * @param message 要签名的消息
     * @return 签名的Base64编码字符串
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public String signMessage(String message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature dsa = Signature.getInstance("SHA256withDSA");
        dsa.initSign(privateKey);
        dsa.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signature = dsa.sign();
        return Base64.getEncoder().encodeToString(signature);
    }

    /**
     * 使用公钥验证消息的签名
     * @param message 要验证的消息
     * @param signature 签名的Base64编码字符串
     * @return 验证结果
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public boolean verifySignature(String message, String signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature dsa = Signature.getInstance("SHA256withDSA");
        dsa.initVerify(publicKey);
        dsa.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] sigBytes = Base64.getDecoder().decode(signature);
        return dsa.verify(sigBytes);
    }

    public static void main(String[] args) {
        try {
            DSASignatureExample1 example = new DSASignatureExample1();

            // 示例消息和签名
            String message = "Hello, DSA!";
            String signature = example.signMessage(message);
            System.out.println("Signature: " + signature);

            // 验证签名
            boolean isValid = example.verifySignature(message, signature);
            System.out.println("Signature valid: " + isValid);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}