import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class ECDSASignatureExample2 {

    public byte[] generateSignature(String message, PrivateKey privateKey) {
        try {
            Signature ecdsa = Signature.getInstance("SHA256withECDSA");
            ecdsa.initSign(privateKey);
            ecdsa.update(message.getBytes());
            return ecdsa.sign();
        } catch (Exception e) {
            System.out.println("Error generating signature: " + e.getMessage());
            return null;
        }
    }

    public boolean verifySignature(String message, byte[] signature, PublicKey publicKey) {
        try {
            Signature ecdsa = Signature.getInstance("SHA256withECDSA");
            ecdsa.initVerify(publicKey);
            ecdsa.update(message.getBytes());
            return ecdsa.verify(signature);
        } catch (Exception e) {
            System.out.println("Error verifying signature: " + e.getMessage());
            return false;
        }
    }

    public static void main(String[] args) {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(256);
            KeyPair keyPair = keyGen.generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            ECDSASignatureExample2 signer = new ECDSASignatureExample2();

            String message = "Hello, ECDSA!";
            byte[] signature = signer.generateSignature(message, privateKey);

            System.out.println("Message: " + message);
            System.out.println("Signature: " + signature);

            boolean verified = signer.verifySignature(message, signature, publicKey);
            System.out.println("Signature verified: " + verified);
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
}