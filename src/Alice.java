import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class Alice {

    public static void main(String[] args) {
        Socket socket;
        PrintWriter printWriter;
        InetAddress inetAddress;
        BufferedReader bufferedReader;
        String receiveData, encodedSecretKey;
        PublicKey publicKeyofBob;
        Key secretKey;
        RSA rsa = new RSA();

        try {
            inetAddress = InetAddress.getByName("127.0.0.1");
            socket = new Socket(inetAddress, 5555);
            bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            //receive the Bob's public key & socket close.
            receiveData = bufferedReader.readLine();
            socket.close();

            //string public key to public key object
            assert receiveData != null;
            publicKeyofBob = encodePublicKey(receiveData);

            //Encryption the plainText by secret key.
            String plainText = "Hello Bob, my name is Alice.";
            secretKey = getAESKey();
            AES aes = new AES();
            String cipherText = aes.encryptionByAES(plainText, secretKey);

            encodedSecretKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
            String cipherKey = rsa.encryptionByRSA(encodedSecretKey, publicKeyofBob);

            String[] sendData = new String[2];
            sendData[0] = cipherText;
            sendData[1] = cipherKey;

            socket = new Socket(inetAddress, 6666);
            //send the encrypted secret key & ciphertext & close socket.
            printWriter = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream())));
            printWriter.write(Arrays.toString(sendData));
            printWriter.flush();

            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static Key getAESKey() {
        String secretKey = "1234567890123456";
        byte[] keyBytes = new byte[16];
        byte[] bytes = secretKey.getBytes(StandardCharsets.UTF_8);

        int length = bytes.length;
        if (bytes.length > keyBytes.length) {
            length = keyBytes.length;
        }

        System.arraycopy(bytes, 0, keyBytes, 0, length);

        return new SecretKeySpec(keyBytes, "AES");
    }

    private static PublicKey encodePublicKey(String stringPublicKey) {
        PublicKey publicKey = null;
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            byte[] bytes = Base64.getDecoder().decode(stringPublicKey.getBytes());
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(bytes);
            publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return publicKey;
    }

}
