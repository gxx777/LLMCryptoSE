import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class ECDSASignatureExample2 {

    private static final String ECDSA_ALGORITHM = "EC";
    private static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";

    private static KeyPair generateECDSAKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ECDSA_ALGORITHM);
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256k1");
        keyPairGenerator.initialize(ecGenParameterSpec);
        return keyPairGenerator.generateKeyPair();
    }

    public static String sign(String message, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        byte[] signatureBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    public static boolean verify(String message, String signature, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signatureInstance = Signature.getInstance(SIGNATURE_ALGORITHM);
        signatureInstance.initVerify(publicKey);
        signatureInstance.update(message.getBytes());
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return signatureInstance.verify(signatureBytes);
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException {
        KeyPair keyPair = generateECDSAKeyPair();
        String message = "This is a sample message to be signed";

        // Sign the message
        String signature = sign(message, keyPair.getPrivate());
        System.out.println("Signature: " + signature);

        // Verify the signature
        boolean isVerified = verify(message, signature, keyPair.getPublic());
        System.out.println("Is signature verified: " + isVerified);
    }
}