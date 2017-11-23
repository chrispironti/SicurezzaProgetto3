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
    
    public static void generateKeyPairs(char[] password, String fileChiaviPubbliche, Map<String,String> filesChiaviPrivate) throws IOException{
        
        JSONObject jPubDatabase = new JSONObject();
        JSONObject jpub = new JSONObject();
        JSONObject jpriv = new JSONObject();
        SecureRandom random = new SecureRandom();
        byte salt[] = new byte[11];
	random.nextBytes(salt);
        byte iv[]= new byte[11];
        random.nextBytes(iv);
        
        for(Map.Entry<String,String> e: filesChiaviPrivate.entrySet()){
            try{
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
                writeKeychain(jpriv, salt, iv, password, fileChiaviPubbliche);
                jPubDatabase.put(e.getKey(), jpub.toString());
            }catch(NoSuchAlgorithmException ex){
                ex.printStackTrace();
                System.exit(1);
            }    
        }
        ObjectOutputStream oos=null;
        try{
        oos = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(fileChiaviPubbliche)));
        oos.writeObject(jPubDatabase.toString());
        oos.close(); 
        }finally{
        if(oos!=null){
            oos.close();
            }  
        }    
    }
    
    public static JSONObject decryptKeychain(char[] password, String fileChiaviPrivate) throws IOException{
        /*Decifra con AES 128 bit il file il cui percorso è passato come parametro, sovrascrivendolo.
        utilizza una password per generare la chiave di decifratura. Ritorna i byte del file decrittato.
        */
        ObjectInputStream ois=null;
        PrivateKey plain = null;
        byte salt[] = new byte[11];
        byte iv[]= new byte[11];
        String s=null;
        try {
            ois = new ObjectInputStream(new BufferedInputStream(new FileInputStream(fileChiaviPrivate)));
            ois.read(salt);
            ois.read(iv);
            Cipher cipher = cipherFromPass(salt, iv, password);
            SealedObject so= (SealedObject) ois.readObject();
            s= (String)so.getObject(cipher);
            ois.close();
	} catch (ClassNotFoundException| IllegalBlockSizeException | 
               BadPaddingException e ) {
            e.printStackTrace();
            System.exit(1);
      	}finally{
            if(ois!=null){
                ois.close();
            }
        }
            return new JSONObject(s);
    }
    
    public static JSONObject getPubKeychain(String KeychainFilePub) throws IOException{
        ObjectInputStream ois=null;
        String s=null;
        try {
            ois = new ObjectInputStream(new BufferedInputStream(new FileInputStream(KeychainFilePub))); 
            s = (String) ois.readObject();
            ois.close();
      	}catch(ClassNotFoundException e){
            e.printStackTrace();
            System.exit(1);
        }
        finally{
            if(ois!=null){
                ois.close();
            }
        }
        return new JSONObject(s); 
    }
    
    public static JSONObject createEmptyKeychain(char[] password,String fileChiaviPrivate) throws IOException{   
        JSONObject jKeychain= new JSONObject("{}");
        SecureRandom random = new SecureRandom();
        byte salt[] = new byte[11];
	random.nextBytes(salt);
        byte iv[]= new byte[11];
        random.nextBytes(iv);
        writeKeychain(jKeychain, salt, iv, password, fileChiaviPrivate);
        return jKeychain;
    }   
    
    private static Cipher cipherFromPass(byte[] salt, byte[] iv, char[] password){
        Cipher cipher=null;
        try{
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec keySpec = new PBEKeySpec(password, salt, 65536, 128);
            SecretKey tmp = factory.generateSecret(keySpec);
            SecretKey secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
            cipher = Cipher.getInstance("AES/CFB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
        }catch(NoSuchAlgorithmException | InvalidAlgorithmParameterException| InvalidKeyException | NoSuchPaddingException | InvalidKeySpecException e){
                e.printStackTrace();
                System.exit(1);
        }
        return cipher;
    }
    
    private static void writeKeychain(JSONObject keychain, byte[] salt, byte[] iv, char[] password, String fileChiaviPrivate) throws IOException{
        ObjectOutputStream oos = null;
        try{
        Cipher cipher= cipherFromPass(salt, iv, password);
        oos = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(fileChiaviPrivate)));
        SealedObject so = new SealedObject(keychain.toString(),cipher);
        oos.write(salt);
        oos.write(iv);
        oos.writeObject(so);
        }catch(IllegalBlockSizeException ex) {
                ex.printStackTrace();
                System.exit(1);
        }
        finally{
            if(oos!=null){
                oos.close();
            }
        }  

    }

    private static void addPassInKeychain(String fileChiaviPrivate, Map<String,String> passToAdd, char[] password){
        
    }
    
    private static void addKeysInKeychain(String fileChiaviPrivate, Map<String,PrivateKey> keyToAdd, char[] password){
        
    }
    
    private static void rmvPassInKeychain(String fileChiaviPrivate, Map<String,String> passToAdd, char[] password){
        
    }
    
    private static void rmvKeysInKeychain(String fileChiaviPrivate, Map<String,PrivateKey> keyToAdd, char[] password){
        
    }

}



