import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.xml.bind.DatatypeConverter;

public class RSASignatureExample2 {

    private static final String ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    public static byte[] sign(String message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        return signature.sign();
    }

    public static boolean verify(String message, byte[] signatureBytes, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(publicKey);
        signature.update(message.getBytes());
        return signature.verify(signatureBytes);
    }

    public static void main(String[] args) throws Exception {
        String message = "Hello, World!";
        
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);

        // Generate key pairs
        // Replace privateKeyStr and publicKeyStr with your actual key strings
        String privateKeyStr = "PRIVATE_KEY_HERE";
        String publicKeyStr = "PUBLIC_KEY_HERE";

        byte[] privateKeyBytes = DatatypeConverter.parseBase64Binary(privateKeyStr);
        byte[] publicKeyBytes = DatatypeConverter.parseBase64Binary(publicKeyStr);

        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8KeySpec);

        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey = keyFactory.generatePublic(x509KeySpec);

        // Sign the message
        byte[] signatureBytes = sign(message, privateKey);

        // Verify the signature
        boolean verified = verify(message, signatureBytes, publicKey);

        System.out.println("Message: " + message);
        System.out.println("Signature: " + DatatypeConverter.printBase64Binary(signatureBytes));
        System.out.println("Verified: " + verified);
    }
}