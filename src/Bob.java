import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class Bob {
    public static void main(String[] args) {
        Socket socket;
        ServerSocket serverSocket;
        BufferedReader bufferedReader;
        PrintWriter printWriter;

        try {
            serverSocket = new ServerSocket(5555);
            //send the public key to Alice.
            RSA rsa = new RSA();
            KeyPair keyPair = rsa.getKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
            String stringPublicKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());

            socket = serverSocket.accept();
            printWriter = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream())));
            printWriter.write(stringPublicKey);
            printWriter.flush();
            socket.close();

            //receive the encrypted secret key & cipherText.
            serverSocket = new ServerSocket(6666);
            socket = serverSocket.accept();
            bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            String receiveData = bufferedReader.readLine();
            socket.close();

            String[] parse = receiveData.split(",");
            String cipherText = parse[0].substring(1);
            String tempCipherKey = parse[1].substring(1, parse[1].length() - 1);

            //Decryption Secret key by Bob's Private key.
            String decryptedCipherKey = rsa.decryptionByRSA(tempCipherKey, privateKey);
            Key secreteKey = decodeSecretKey(decryptedCipherKey);

            //Decryption cipher text by secret key.
            AES aes = new AES();
            String plainText = aes.decryptionByAES(cipherText, secreteKey);
            System.out.println(plainText);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static Key decodeSecretKey(String encodedSecretKey) {
        byte[] decodedKey = Base64.getDecoder().decode(encodedSecretKey);

        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }

}
