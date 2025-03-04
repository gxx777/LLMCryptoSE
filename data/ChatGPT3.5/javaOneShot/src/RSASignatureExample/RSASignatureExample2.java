import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class RSASignatureExample2 {

    private static final String ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public RSASignatureExample2() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
            keyPairGenerator.initialize(2048); // Using a secure key length
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            privateKey = keyPair.getPrivate();
            publicKey = keyPair.getPublic();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public byte[] sign(byte[] message) {
        try {
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initSign(privateKey);
            signature.update(message);
            return signature.sign();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public boolean verify(byte[] message, byte[] signature) {
        try {
            Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
            sig.initVerify(publicKey);
            sig.update(message);
            return sig.verify(signature);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static void main(String[] args) {
        RSASignatureExample2 rsaSignatureExample = new RSASignatureExample2();

        String message = "This is a secret message to be signed";
        byte[] signature = rsaSignatureExample.sign(message.getBytes());
        System.out.println("Signature: " + new String(signature));

        boolean isValid = rsaSignatureExample.verify(message.getBytes(), signature);
        System.out.println("Is the signature valid? " + isValid);
    }
}