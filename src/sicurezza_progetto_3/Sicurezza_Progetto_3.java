/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sicurezza_progetto_3;
 import java.sql.Timestamp;
import java.io.*;
import java.security.*;
import javax.crypto.*;
import org.json.*;
/**
 *
 * @author Daniele
 */
public class Sicurezza_Progetto_3 {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws UnsupportedEncodingException, FileNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, IOException {
        // TODO code application logic here
        JSONObject j = new JSONObject();
        j.put("Chiave","Prova");
        String str = j.toString();
        byte[] plaintext = str.getBytes("UTF-8");
        SecureRandom random = new SecureRandom();
        KeyPairGenerator keyPairGenerator = null;
        keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024,random);
        KeyPair RSAKeys1024 = keyPairGenerator.generateKeyPair();
        PublicKey rsapublickey = RSAKeys1024.getPublic();
        PrivateKey rsaprivatekey = RSAKeys1024.getPrivate();
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding");
        c.init(Cipher.ENCRYPT_MODE, rsapublickey);
        byte[] ciphertext = c.doFinal(plaintext);
        BufferedOutputStream  bos = new BufferedOutputStream(new FileOutputStream("test.txt"));
        bos.write(ciphertext);
        bos.close();
        c.init(Cipher.DECRYPT_MODE, rsaprivatekey);
        CipherInputStream cis = new CipherInputStream(new FileInputStream("test.txt"), c);
        //BufferedOutputStream  bosdec = new BufferedOutputStream(new FileOutputStream("testdec.txt"));
        byte [] buffer = new byte [1024];  
        int r;  
        String read = "";
        while ((r = cis.read(buffer)) > 0) {  
            read+=new String(buffer);  
        }  
        cis.close();  
        JSONObject jnew = new JSONObject(read);
        System.out.println(jnew.toString());
    }
    
}
