import java.security.*;

public class DSASignatureExample3 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public DSASignatureExample3() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        keyPairGenerator.initialize(1024, random);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public byte[] sign(String message) throws Exception {
        Signature dsa = Signature.getInstance("SHA256withDSA");
        dsa.initSign(privateKey);
        dsa.update(message.getBytes());
        return dsa.sign();
    }

    public boolean verify(String message, byte[] signature) throws Exception {
        Signature dsa = Signature.getInstance("SHA256withDSA");
        dsa.initVerify(publicKey);
        dsa.update(message.getBytes());
        return dsa.verify(signature);
    }

    public static void main(String[] args) {
        try {
            DSASignatureExample3 example = new DSASignatureExample3();

            // 消息内容
            String message = "Hello, DSA Signature Example!";

            // 对消息进行签名
            byte[] signature = example.sign(message);

            // 验证签名
            boolean isValid = example.verify(message, signature);
            System.out.println("Signature is valid: " + isValid);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}