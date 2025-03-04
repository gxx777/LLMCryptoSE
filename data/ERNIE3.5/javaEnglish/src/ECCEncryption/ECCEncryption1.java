//import org.bouncycastle.crypto.CipherParameters;
//import org.bouncycastle.crypto.engines.AESEngine;
//import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
//import org.bouncycastle.crypto.modes.CBCBlockCipher;
//import org.bouncycastle.crypto.modes.PaddingMode;
//import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
//import org.bouncycastle.crypto.params.ECPublicKeyParameters;
//import org.bouncycastle.crypto.params.KeyParameter;
//import org.bouncycastle.crypto.util.Hex;
//import org.bouncycastle.jce.ECNamedCurveTable;
//import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
//
//import java.io.File;
//import java.io.FileInputStream;
//import java.io.FileOutputStream;
//import java.io.IOException;
//import java.security.KeyPair;
//import java.security.KeyPairGenerator;
//import java.security.SecureRandom;
//import java.security.spec.ECGenParameterSpec;
//
//public class ECCEncryption1 {
//
//    private static final String ECC_CURVE = "secp256r1";
//    private static final String SYMMETRIC_KEY = "ThisIsASymmetricKey1234567890";
//
//    public static void main(String[] args) throws Exception {
//        // Generate ECC key pair
//        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
//        ECGenParameterSpec ecSpec = new ECGenParameterSpec(ECC_CURVE);
//        keyPairGenerator.initialize(ecSpec, new SecureRandom());
//        KeyPair keyPair = keyPairGenerator.generateKeyPair();
//        ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters) ECNamedCurveTable.getParameterSpec(ECC_CURVE).getCurve().decodePoint(keyPair.getPrivate().getEncoded());
//        ECPublicKeyParameters publicKey = (ECPublicKeyParameters) ECNamedCurveTable.getParameterSpec(ECC_CURVE).getCurve().decodePoint(keyPair.getPublic().getEncoded());
//
//        // Encrypt the symmetric key using ECC public key
//        byte[] encryptedSymmetricKey = encrypt(SYMMETRIC_KEY.getBytes(), publicKey);
//
//        // Decrypt the symmetric key using ECC private key
//        byte[] decryptedSymmetricKey = decrypt(encryptedSymmetricKey, privateKey);
//
//        // Output the results
//        System.out.println("Original Symmetric Key: " + new String(SYMMETRIC_KEY.getBytes()));
//        System.out.println("Encrypted Symmetric Key: " + Hex.toHexString(encryptedSymmetricKey));
//        System.out.println("Decrypted Symmetric Key: " + new String(decryptedSymmetricKey));
//
//        // Save the encrypted symmetric key to a file
//        saveEncryptedKeyToFile(encryptedSymmetricKey, "encrypted_symmetric_key.bin");
//
//        // Read and decrypt the encrypted symmetric key from the file
//        byte[] readEncryptedSymmetricKey = readEncryptedKeyFromFile("encrypted_symmetric_key.bin");
//        byte[] readDecryptedSymmetricKey = decrypt(readEncryptedSymmetricKey, privateKey);
//        System.out.println("Decrypted Symmetric Key from file: " + new String(readDecryptedSymmetricKey));
//    }
//
//    private static byte[] encrypt(byte[] data, ECPublicKeyParameters publicKey) throws Exception {
//        AESEngine aesEngine = new AESEngine();
//        CBCBlockCipher cipher = new CBCBlockCipher(aesEngine);
//        cipher.init(true, new CipherParameters(publicKey));
//
//        byte[] output = new byte[cipher.getOutputSize(data.length)];
//        int outputLen = cipher.processBytes(data, 0, data.length, output, 0);
//        cipher.doFinal(output, outputLen);
//
//        return output;
//    }
//
//}