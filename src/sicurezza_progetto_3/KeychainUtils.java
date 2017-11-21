/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sicurezza_progetto_3;

import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.json.*;

/**
 *
 * DA MODIFICARE
 */
public class KeychainUtils {
    
    
    public static void generateKeyPairs(char[] password, String fileChiaviPubbliche, String fileChiaviPrivate) throws IOException{
        
        JSONObject jpub = new JSONObject();
        JSONObject jpriv = new JSONObject();
        SecureRandom random = new SecureRandom();
        byte salt[] = new byte[11];
	random.nextBytes(salt);
        byte iv[]= new byte[11];
        random.nextBytes(iv);
        ObjectOutputStream oos = null;
        
            try {     
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                KeySpec keySpec = new PBEKeySpec(password, salt, 65536, 128);
                SecretKey tmp = factory.generateSecret(keySpec);
                SecretKey secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
                Cipher cipher = Cipher.getInstance("AES/CFB/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
                KeyPairGenerator keyPairGenerator = null;
                keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(1024,random);
                KeyPair RSAKeys1024 = keyPairGenerator.generateKeyPair();
                jpub.put("ChiaveRSA1024Pub", Base64.getEncoder().encodeToString(RSAKeys1024.getPublic().getEncoded()));
                jpriv.put("ChiaveRSA1024Priv", Base64.getEncoder().encodeToString(RSAKeys1024.getPrivate().getEncoded()));
                //Generazione chiavi RSA 2048
                keyPairGenerator.initialize(2048,random);
                KeyPair RSAKeys2048 = keyPairGenerator.generateKeyPair();
                jpub.put("ChiaveRSA2048Pub", Base64.getEncoder().encodeToString(RSAKeys2048.getPublic().getEncoded()));
                jpriv.put("ChiaveRSA2048Priv", Base64.getEncoder().encodeToString(RSAKeys2048.getPrivate().getEncoded()));
                //Generazione chiavi DSA 1024
                keyPairGenerator = KeyPairGenerator.getInstance("DSA");
                keyPairGenerator.initialize(1024,random);
                KeyPair DSAKeys1024 = keyPairGenerator.generateKeyPair();
                jpub.put("ChiaveDSA1024Pub", Base64.getEncoder().encodeToString(DSAKeys1024.getPublic().getEncoded()));
                jpriv.put("ChiaveDSA1024Priv", Base64.getEncoder().encodeToString(DSAKeys1024.getPrivate().getEncoded()));
                //Generazione chiavi DSA 2048
                keyPairGenerator.initialize(2048,random);
                KeyPair DSAKeys2048 = keyPairGenerator.generateKeyPair();
                jpub.put("ChiaveDSA2048Pub", Base64.getEncoder().encodeToString(DSAKeys2048.getPublic().getEncoded()));
                jpriv.put("ChiaveDSA2048Priv", Base64.getEncoder().encodeToString(DSAKeys2048.getPrivate().getEncoded()));
                SealedObject so = new SealedObject(jpriv.toString(),cipher);
                oos = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(fileChiaviPrivate)));
                oos.write(salt);
                oos.write(iv);
                oos.writeObject(so);
                oos.close();   
                oos = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(fileChiaviPubbliche)));
                oos.writeObject(jpub.toString());
                oos.close(); 
            } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | IllegalBlockSizeException| InvalidKeyException | NoSuchPaddingException | InvalidKeySpecException e) {
                e.printStackTrace();
                System.exit(1);
            }finally{
                if(oos!=null){
                    oos.close();
                }
            }    
    }
    
    public static JSONObject decryptKeychain(char[] password, String fileChiaviPrivate) throws IOException, BadPaddingException{
        /*Decifra con AES 128 bit il file il cui percorso è passato come parametro, sovrascrivendolo.
        utilizza una password per generare la chiave di decifratura. Ritorna i byte del file decrittato.
        */
        ObjectInputStream ois=null;
        PrivateKey plain = null;
        byte salt[] = new byte[11];
        byte iv[]= new byte[11];
        String s=null;
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            ois = new ObjectInputStream(new BufferedInputStream(new FileInputStream(fileChiaviPrivate)));
            ois.read(salt);
            ois.read(iv);
            KeySpec keySpec = new PBEKeySpec(password, salt, 65536, 128);
            SecretKey tmp = factory.generateSecret(keySpec);
            SecretKey secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
            Cipher cipher = Cipher.getInstance("AES/CFB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
            SealedObject so= (SealedObject) ois.readObject();
            s= (String)so.getObject(cipher);
            ois.close();
	} catch (ClassNotFoundException|NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | InvalidAlgorithmParameterException e ) {
            e.printStackTrace();
            System.exit(1);
      	}finally{
            if(ois!=null){
                ois.close();
            }
        }
            return new JSONObject(s);
    }
}
