//import org.bouncycastle.crypto.CipherParameters;
//import org.bouncycastle.crypto.engines.AESEngine;
//import org.bouncycastle.crypto.modes.CTRBlockCipher;
//import org.bouncycastle.crypto.params.KeyParameter;
//import org.bouncycastle.crypto.params.ParametersWithIV;
//
//import javax.crypto.spec.SecretKeySpec;
//import java.nio.charset.StandardCharsets;
//import java.security.Security;
//import java.util.Base64;
//
//public class SymmetricEncryptionCTR1 {
//
//    static {
//        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
//    }
//
//    /**
//     * 使用AES和CTR模式加密字符串
//     *
//     * @param plainText  要加密的明文
//     * @param key        加密密钥
//     * @param initialIV  初始向量（计数器初始值）
//     * @return 加密后的密文（Base64编码）
//     * @throws Exception 如果加密失败
//     */
//    public static String encrypt(String plainText, byte[] key, byte[] initialIV) throws Exception {
//        AESEngine engine = new AESEngine();
//        CTRBlockCipher cipher = new CTRBlockCipher(engine);
//        cipher.init(true, new ParametersWithIV(new KeyParameter(key), initialIV));
//
//        byte[] input = plainText.getBytes(StandardCharsets.UTF_8);
//        byte[] output = new byte[cipher.getOutputSize(input.length)];
//        int len1 = cipher.processBytes(input, 0, input.length, output, 0);
//        cipher.doFinal(output, len1);
//
//        return Base64.getEncoder().encodeToString(output);
//    }
//
//    /**
//     * 使用AES和CTR模式解密字符串
//     *
//     * @param cipherText 要解密的密文（Base64编码）
//     * @param key        解密密钥
//     * @param initialIV  初始向量（计数器初始值）
//     * @return 解密后的明文
//     * @throws Exception 如果解密失败
//     */
//    public static String decrypt(String cipherText, byte[] key, byte[] initialIV) throws Exception {
//        AESEngine engine = new AESEngine();
//        CTRBlockCipher cipher = new CTRBlockCipher(engine);
//        cipher.init(false, new ParametersWithIV(new KeyParameter(key), initialIV));
//
//        byte[] input = Base64.getDecoder().decode(cipherText);
//        byte[] output = new byte[cipher.getOutputSize(input.length)];
//        int len1 = cipher.processBytes(input, 0, input.length, output, 0);
//        cipher.doFinal(output, len1);
//
//        return new String(output, StandardCharsets.UTF_8);
//    }
//
//    public static void main(String[] args) {
//        try {
//            // 示例密钥和初始向量（计数器初始值）
//            byte[] key = "ThisIsASecretKey123".getBytes(StandardCharsets.UTF_8);
//            byte[] initialIV = new byte[16]; // CTR模式需要的IV长度与AES块大小相同，对于AES-128是16字节
//
//            // 加密
//            String plainText = "Hello, World!";
//            String cipherText = encrypt(plainText, key, initialIV);
//            System.out.println("Encrypted Text: " + cipherText);
//
//            // 解密
//            String decryptedText = decrypt(cipherText, key, initialIV);
//            System.out.println("Decrypted Text: " + decryptedText);
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//    }
//}