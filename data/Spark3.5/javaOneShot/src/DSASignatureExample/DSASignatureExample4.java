import java.security.*;
import java.util.Base64;

public class DSASignatureExample4 {

    private static final String ALGORITHM = "SHA256withDSA";
    private KeyPair keyPair;

    public DSASignatureExample4() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(2048);
        keyPair = keyPairGenerator.generateKeyPair();
    }

    public String sign(String message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature dsa = Signature.getInstance(ALGORITHM);
        dsa.initSign(keyPair.getPrivate());
        dsa.update(message.getBytes());
        byte[] signedMessage = dsa.sign();
        return Base64.getEncoder().encodeToString(signedMessage);
    }

    public boolean verify(String message, String signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature dsa = Signature.getInstance(ALGORITHM);
        dsa.initVerify(keyPair.getPublic());
        dsa.update(message.getBytes());
        byte[] decodedSignature = Base64.getDecoder().decode(signature);
        return dsa.verify(decodedSignature);
    }

    public static void main(String[] args) {
        try {
            DSASignatureExample4 example = new DSASignatureExample4();
            String message = "Hello, DSA!";
            String signature = example.sign(message);
            System.out.println("签名： " + signature);

            boolean isVerified = example.verify(message, signature);
            System.out.println("验签结果： " + (isVerified ? "成功" : "失败"));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}