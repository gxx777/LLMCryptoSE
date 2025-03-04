import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

public class ECDSASignatureExample4 {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public void generateKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1")); // 使用secp256r1曲线
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    public String sign(String message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initSign(this.privateKey);
        ecdsa.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] realSig = ecdsa.sign();
        return Base64.getEncoder().encodeToString(realSig);
    }

    public boolean verify(String message, String signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initVerify(this.publicKey);
        ecdsa.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] sigBytes = Base64.getDecoder().decode(signature);
        return ecdsa.verify(sigBytes);
    }

    public static void main(String[] args) throws Exception {
        ECDSASignatureExample4 ecdsaExample = new ECDSASignatureExample4();
        ecdsaExample.generateKeyPair();

        String message = "Hello, ECDSA!";
        String signature = ecdsaExample.sign(message);
        System.out.println("Signature: " + signature);

        boolean isValid = ecdsaExample.verify(message, signature);
        System.out.println("Signature valid: " + isValid);
    }
}