import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

public class AesEncryptionImage {
    private static byte[] priEncryptionImage(SecretKey secretKey, byte[] content) {
        Cipher cipher;
        byte[] encrypted = null;
        try {
            cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            encrypted = Base64.getEncoder().encode(cipher.doFinal(content));

        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return encrypted;
    }

    public static byte[] encryptionImage(SecretKey secretKey, byte[] content) {
        return priEncryptionImage(secretKey, content);
    }

    private static byte[] priDecryptionImage(SecretKey secretKey, byte[] textCrypt) {
        Cipher cipher;
        byte[] decrypted = null;
        try {
            cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");

            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            decrypted = cipher.doFinal(Base64.getDecoder().decode(textCrypt));

        } catch (Exception e) {

            System.out.println("Error while decrypting: " + e.toString());
        }
        return decrypted;
    }

    public static byte[] decryptionImage(SecretKey secretKey, byte[] textCrypt) {
        return priDecryptionImage(secretKey, textCrypt);
    }

    private static byte[] priGetFile() {
        File f = new File("");
        InputStream is = null;
        try {
            is = new FileInputStream(f);
        } catch (FileNotFoundException e2) {
            e2.printStackTrace();
        }
        byte[] content = null;
        try {
            assert is != null;
            content = new byte[is.available()];
        } catch (IOException e1) {
            e1.printStackTrace();
        }
        try {
            assert content != null;
            is.read(content);
        } catch (IOException e) {
            e.printStackTrace();
        }

        return content;
    }

    public static byte[] getFile() {
        return priGetFile();
    }

    private static void priSaveFile(byte[] bytes) {
        try{
            FileOutputStream fos = new FileOutputStream("");
            fos.write(bytes);
            fos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void saveFile(byte[] bytes) {
        priSaveFile(bytes);
    }

    public static void main(String[] args) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        SecretKeySpec secretKey;
        byte[] key;
        String myKey = "ThisIsAStrongPasswordForEncryptionAndDecryption";

        MessageDigest sha = null;
        key = myKey.getBytes("UTF-8");
        System.out.println(key.length);
        sha = MessageDigest.getInstance("SHA-1");
        key = sha.digest(key);
        key = Arrays.copyOf(key, 16); // use only first 128 bit
        System.out.println(key.length);
        System.out.println(new String(key, "UTF-8"));
        secretKey = new SecretKeySpec(key, "AES");

        byte[] content = getFile();
        System.out.println(content);

        byte[] encrypted = encryptionImage(secretKey, content);
        System.out.println(encrypted);

        byte[] decrypted = decryptionImage(secretKey, encrypted);
        System.out.println(decrypted);

        saveFile(decrypted);
//        saveFile(encrypted);
        System.out.println("Done");
    }
}
