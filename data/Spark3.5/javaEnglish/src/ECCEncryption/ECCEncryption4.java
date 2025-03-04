import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Arrays;

public class ECCEncryption4 {
    private static final String ALGORITHM = "ECDH";
    private static final String PROVIDER = "BC";
    private static final String CURVE_NAME = "secp256r1";

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // Generate ECC key pair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHM, PROVIDER);
//        kpg.initialize(new ECNamedCurveParameterSpec(CURVE_NAME));
        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(CURVE_NAME);
        kpg.initialize(ecSpec);
        KeyPair kp = kpg.generateKeyPair();
        PublicKey publicKey = kp.getPublic();
        PrivateKey privateKey = kp.getPrivate();

        // Encrypt
        byte[] plaintext = "Hello, World!".getBytes();
        byte[] ciphertext = encrypt(plaintext, publicKey);
        System.out.println("Ciphertext: " + Arrays.toString(ciphertext));

        // Decrypt
        byte[] decryptedText = decrypt(ciphertext, privateKey);
        System.out.println("Decrypted text: " + new String(decryptedText));
    }

    public static byte[] encrypt(byte[] plaintext, PublicKey publicKey) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance(ALGORITHM, PROVIDER);
        ka.init(publicKey);
        ECPoint sharedPoint = ((org.bouncycastle.jce.interfaces.ECPublicKey) publicKey).getQ();
        byte[] secretKey = ka.generateSecret();

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(secretKey, "AES"));
        return cipher.doFinal(plaintext);
    }

    public static byte[] decrypt(byte[] ciphertext, PrivateKey privateKey) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance(ALGORITHM, PROVIDER);
        ka.init(privateKey);
//        ECPoint sharedPoint = ((org.bouncycastle.jce.interfaces.ECPrivateKey) privateKey).getD();
        ECPoint sharedPoint = ((org.bouncycastle.jce.interfaces.ECPublicKey) privateKey).getQ();
        byte[] secretKey = ka.generateSecret();

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(secretKey, "AES"));
        return cipher.doFinal(ciphertext);
    }
}