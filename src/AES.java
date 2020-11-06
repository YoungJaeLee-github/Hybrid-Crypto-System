import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AES {
    private String priEncryptionByAES(String plainText, Key secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException {
        String initializeVector = "0987654321654321";
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(initializeVector.getBytes(StandardCharsets.UTF_8)));
        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        return Base64.getEncoder().encodeToString(encrypted);

    }

    private String priDecryptionByAES(String cipherText, Key secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        String initializeVector = "0987654321654321";
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(initializeVector.getBytes(StandardCharsets.UTF_8)));
        byte[] decrypted = Base64.getDecoder().decode(cipherText.getBytes(StandardCharsets.UTF_8));

        return new String(cipher.doFinal(decrypted), StandardCharsets.UTF_8);
    }

    public String encryptionByAES(String plainText, Key secretKey) {
        String result = "";
        try {
            result = priEncryptionByAES(plainText, secretKey);
        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return result;
    }

    public String decryptionByAES(String cipherText, Key secretKey) {
        String result = "";
        try {
            result = priDecryptionByAES(cipherText, secretKey);
        } catch (NoSuchAlgorithmException | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return result;
    }
}
