import java.security.*;
import javax.crypto.Cipher;

public class SignatureExample4 {
    private PublicKey publicKey;
    private PrivateKey privateKey;

    public SignatureExample4() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair pair = keyGen.generateKeyPair();
        this.publicKey = pair.getPublic();
        this.privateKey = pair.getPrivate();
    }

    public byte[] sign(String plainText) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes());
        return privateSignature.sign();
    }

    public boolean verify(String plainText, byte[] signatureBytes) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes());
        return publicSignature.verify(signatureBytes);
    }
}