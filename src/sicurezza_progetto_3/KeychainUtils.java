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
    
    public static final int IV_SIZE=16;
    public static final int SALT_SIZE=16;
    
    public static void generateKeyPairs(Map<String,char[]> passwords, String fileChiaviPubbliche, Map<String,String> filesChiaviPrivate) throws IOException{
        
        JSONObject jPubDatabase = new JSONObject();
        JSONObject jpub = new JSONObject();
        JSONObject jpriv = new JSONObject();
        SecureRandom random = new SecureRandom();
        byte salt[] = new byte[SALT_SIZE];
	random.nextBytes(salt);
        byte iv[]= new byte[IV_SIZE];
        random.nextBytes(iv);
        
        for(Map.Entry<String,String> e: filesChiaviPrivate.entrySet()){
            try{
                KeyPairGenerator keyPairGenerator = null;
                keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(1024, new SecureRandom());
                KeyPair RSAKeys1024 = keyPairGenerator.generateKeyPair();
                jpub.put("Key/RSA/1024/Main", Base64.getEncoder().encodeToString(RSAKeys1024.getPublic().getEncoded()));
                jpriv.put("Key/RSA/1024/Main", Base64.getEncoder().encodeToString(RSAKeys1024.getPrivate().getEncoded()));
                //Generazione chiavi RSA 2048
                keyPairGenerator.initialize(2048, new SecureRandom());
                KeyPair RSAKeys2048 = keyPairGenerator.generateKeyPair();
                jpub.put("Key/RSA/2048/Main", Base64.getEncoder().encodeToString(RSAKeys2048.getPublic().getEncoded()));
                jpriv.put("Key/RSA/2048/Main", Base64.getEncoder().encodeToString(RSAKeys2048.getPrivate().getEncoded()));
                //Generazione chiavi DSA 1024
                keyPairGenerator = KeyPairGenerator.getInstance("DSA");
                keyPairGenerator.initialize(1024, new SecureRandom());
                KeyPair DSAKeys1024 = keyPairGenerator.generateKeyPair();
                jpub.put("Key/DSA/1024/Main", Base64.getEncoder().encodeToString(DSAKeys1024.getPublic().getEncoded()));
                jpriv.put("Key/DSA/1024/Main", Base64.getEncoder().encodeToString(DSAKeys1024.getPrivate().getEncoded()));
                //Generazione chiavi DSA 2048
                keyPairGenerator.initialize(2048, new SecureRandom());
                KeyPair DSAKeys2048 = keyPairGenerator.generateKeyPair();
                jpub.put("Key/DSA/2048/Main", Base64.getEncoder().encodeToString(DSAKeys2048.getPublic().getEncoded()));
                jpriv.put("Key/DSA/2048/Main", Base64.getEncoder().encodeToString(DSAKeys2048.getPrivate().getEncoded()));
                char[] password = passwords.get(e.getKey());
                if(password != null){
                    writeKeychain(jpriv, salt, iv, passwords.get(e.getKey()), e.getValue());
                    jPubDatabase.put(e.getKey(), jpub.toString());
                }else
                    System.out.println("Errore. L'utente non è presente in entrambe le mappe. La richiesta verrà ignorata.\n");
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
    
    public static JSONObject decryptKeychain(char[] password, String fileChiaviPrivate, byte[] salt, byte[] iv) throws IOException{
        /*Decifra con AES 128 bit il file il cui percorso è passato come parametro, sovrascrivendolo.
        utilizza una password per generare la chiave di decifratura. Ritorna i byte del file decrittato.
        */
        ObjectInputStream ois=null;
        PrivateKey plain = null;
        String s=null;
        try {
            ois = new ObjectInputStream(new BufferedInputStream(new FileInputStream(fileChiaviPrivate)));
            ois.read(salt);
            ois.read(iv);
            Cipher cipher = cipherFromPass(salt, iv, password,false);
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
    
    public static JSONObject decryptKeychain(char[] password, String fileChiaviPrivate) throws IOException{
        /*Decifra con AES 128 bit il file il cui percorso è passato come parametro, sovrascrivendolo.
        utilizza una password per generare la chiave di decifratura. Ritorna i byte del file decrittato.
        */ 
        byte[] iv = new byte[IV_SIZE];
        byte[] salt= new byte[SALT_SIZE];
        ObjectInputStream ois=null;
        String s=null;
        try {
            ois = new ObjectInputStream(new BufferedInputStream(new FileInputStream(fileChiaviPrivate)));
            ois.read(salt);
            ois.read(iv);
            Cipher cipher = cipherFromPass(salt, iv, password,false);
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
    
        public static Cipher cipherFromPass(byte[] salt, byte[] iv, char[] password,boolean isEnc){
        Cipher cipher=null;
        try{
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec keySpec = new PBEKeySpec(password, salt, 65536, 128);
            SecretKey tmp = factory.generateSecret(keySpec);
            SecretKey secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
            cipher = Cipher.getInstance("AES/CFB/PKCS5Padding");
            if(isEnc){
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
            }else{
                cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
            }
        }catch(NoSuchAlgorithmException | InvalidAlgorithmParameterException| InvalidKeyException | NoSuchPaddingException | InvalidKeySpecException e){
                e.printStackTrace();
                System.exit(1);
        }
        return cipher;
    }
    
    private static void writeKeychain(JSONObject keychain, byte[] salt, byte[] iv, char[] password, String fileChiaviPrivate) throws IOException{
        ObjectOutputStream oos = null;
        try{
        Cipher cipher= cipherFromPass(salt, iv, password,true);
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
        /* L'identificativo è posto per convenzione Pass/Service/AccountOnTheService*/

    public static void addPassInKeychain(String fileChiaviPrivate, Map<String,String> passToAdd, char[] password) throws IOException{
        byte[] salt= new byte[SALT_SIZE];
        byte[] iv= new byte[IV_SIZE];
        JSONObject keychain = decryptKeychain(password, fileChiaviPrivate,salt,iv);
        for(Map.Entry<String,String> entry :passToAdd.entrySet()){
            keychain.put(entry.getKey(), entry.getValue());
        }
        writeKeychain(keychain, salt, iv, password, fileChiaviPrivate);
    }
    
        /* L'identificativo è posto per convenzione Key/TYPE/dim/Service*/

    public static void addKeysInKeychain(String fileChiaviPrivate, Map<String,PrivateKey> keyToAdd, char[] password) throws IOException{
        byte[] salt= new byte[SALT_SIZE];
        byte[] iv= new byte[IV_SIZE];
        JSONObject keychain = decryptKeychain(password, fileChiaviPrivate,salt,iv);
        for(Map.Entry<String,PrivateKey> entry :keyToAdd.entrySet()){
            keychain.put(entry.getKey(), Base64.getEncoder().encodeToString(entry.getValue().getEncoded()));
        }
        writeKeychain(keychain, salt, iv, password, fileChiaviPrivate);
    }
    
    public static void rmvInKeychain(String fileChiaviPrivate, List<String> ids, char[] password) throws IOException{
        byte[] salt = new byte[SALT_SIZE];
        byte[] iv= new byte[IV_SIZE];
        JSONObject keychain = decryptKeychain(password, fileChiaviPrivate,salt,iv);
        for(String s: ids){
            keychain.remove(s);
        }
        writeKeychain(keychain, salt, iv, password, fileChiaviPrivate);     
    }
    
    

}



