import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class ECDSASignatureExample2 {

    private static final String ALGORITHM = "SHA256withECDSA";
    private static final String ECC_CURVE_NAME = "secp256k1";

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public ECDSASignatureExample2() {
        try {
            KeyPair keyPair = generateECKeyPair();
            this.privateKey = keyPair.getPrivate();
            this.publicKey = keyPair.getPublic();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String sign(String message) {
        try {
            Signature signature = Signature.getInstance(ALGORITHM);
            signature.initSign(privateKey);
            signature.update(message.getBytes());
            byte[] signatureBytes = signature.sign();
            return Base64.getEncoder().encodeToString(signatureBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public boolean verify(String message, String signature) {
        try {
            Signature sig = Signature.getInstance(ALGORITHM);
            sig.initVerify(publicKey);
            sig.update(message.getBytes());
            return sig.verify(Base64.getDecoder().decode(signature));
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    private KeyPair generateECKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(ECC_CURVE_NAME);
        keyPairGenerator.initialize(ecGenParameterSpec);
        return keyPairGenerator.generateKeyPair();
    }

    public static void main(String[] args) {
        ECDSASignatureExample2 example = new ECDSASignatureExample2();

        String message = "Hello, this is a message to be signed";
        String signature = example.sign(message);

        System.out.println("Message: " + message);
        System.out.println("Signature: " + signature);

        System.out.println("Verification result: " + example.verify(message, signature));
    }
}