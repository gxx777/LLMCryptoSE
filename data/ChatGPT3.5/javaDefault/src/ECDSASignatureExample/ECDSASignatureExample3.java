import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;

public class ECDSASignatureExample3 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public ECDSASignatureExample3() {
        try {
            // Generate key pair
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            keyPairGenerator.initialize(256);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            privateKey = keyPair.getPrivate();
            publicKey = keyPair.getPublic();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public byte[] signMessage(byte[] message) {
        byte[] signature = null;
        try {
            Signature ecdsa = Signature.getInstance("SHA256withECDSA");
            ecdsa.initSign(privateKey);
            ecdsa.update(message);
            signature = ecdsa.sign();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return signature;
    }

    public boolean verifySignature(byte[] message, byte[] signature) {
        try {
            Signature ecdsa = Signature.getInstance("SHA256withECDSA");
            ecdsa.initVerify(publicKey);
            ecdsa.update(message);
            return ecdsa.verify(signature);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static void main(String[] args) {
        ECDSASignatureExample3 example = new ECDSASignatureExample3();
        String message = "Hello, World!";
        byte[] messageBytes = message.getBytes();
        byte[] signature = example.signMessage(messageBytes);
        System.out.println("Signature: " + Arrays.toString(signature));
        boolean isVerified = example.verifySignature(messageBytes, signature);
        System.out.println("Signature verified: " + isVerified);
    }
}