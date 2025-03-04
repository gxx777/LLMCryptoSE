import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class DSASignatureExample3 {

    private static final String ALGORITHM = "DSA";

    public static byte[] sign(String message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance(ALGORITHM);
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        return signature.sign();
    }

    public static boolean verify(String message, byte[] signature, PublicKey publicKey) throws Exception {
        Signature sign = Signature.getInstance(ALGORITHM);
        sign.initVerify(publicKey);
        sign.update(message.getBytes());
        return sign.verify(signature);
    }

    public static void main(String[] args) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
            keyPairGenerator.initialize(1024);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            String message = "Hello, world!";
            byte[] signature = sign(message, keyPair.getPrivate());
            System.out.println("Signature: " + new String(signature));

            boolean verified = verify(message, signature, keyPair.getPublic());
            System.out.println("Signature verified: " + verified);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}