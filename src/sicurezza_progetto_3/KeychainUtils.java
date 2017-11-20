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
    
    
    private static final byte salt[] = {69, 121, 101, 45, 62, 118, 101, 114, 61, 101, 98};
    private static final byte iv[] = {-74, -115, 30, 2, 40, 126, 83, -57, 50, 17, 87, -123, -10, 47, -127, 77};
    
    
    public static void generateKeyPairs(Map<String,char[]> utenti, String fileChiaviPubbliche, String fileChiaviPrivate) throws IOException{
        //String keys = new String(Files.readAllBytes(p));
        
        JSONObject pubKeychain = new JSONObject();
        JSONObject privKeychain = new JSONObject();
        JSONObject jpub = new JSONObject();
        JSONObject jpriv = new JSONObject();
        for(Map.Entry<String, char[]> entry : utenti.entrySet()){
            try {     
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                KeySpec keySpec = new PBEKeySpec(entry.getValue(), salt, 65536, 128);
                SecretKey tmp = factory.generateSecret(keySpec);
                SecretKey secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
                Cipher cipher = Cipher.getInstance("AES/CFB/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
                KeyPairGenerator keyPairGenerator = null;
                keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(1024, new SecureRandom());
                KeyPair RSAKeys1024 = keyPairGenerator.generateKeyPair();
                jpub.put("ChiaveRSA1024Pub", Base64.getEncoder().encodeToString(RSAKeys1024.getPublic().getEncoded()));
                jpriv.put("ChiaveRSA1024Priv", Base64.getEncoder().encodeToString(cipher.doFinal(RSAKeys1024.getPrivate().getEncoded())));
                //Generazione chiavi RSA 2048
                keyPairGenerator.initialize(2048, new SecureRandom());
                KeyPair RSAKeys2048 = keyPairGenerator.generateKeyPair();
                jpub.put("ChiaveRSA2048Pub", Base64.getEncoder().encodeToString(RSAKeys2048.getPublic().getEncoded()));
                jpriv.put("ChiaveRSA2048Priv", Base64.getEncoder().encodeToString(cipher.doFinal(RSAKeys2048.getPrivate().getEncoded())));
                //Generazione chiavi DSA 1024
                keyPairGenerator = KeyPairGenerator.getInstance("DSA");
                keyPairGenerator.initialize(1024, new SecureRandom());
                KeyPair DSAKeys1024 = keyPairGenerator.generateKeyPair();
                jpub.put("ChiaveDSA1024Pub", Base64.getEncoder().encodeToString(DSAKeys1024.getPublic().getEncoded()));
                jpriv.put("ChiaveDSA1024Priv", Base64.getEncoder().encodeToString(cipher.doFinal(DSAKeys1024.getPrivate().getEncoded())));
                //Generazione chiavi DSA 2048
                keyPairGenerator.initialize(2048, new SecureRandom());
                KeyPair DSAKeys2048 = keyPairGenerator.generateKeyPair();
                jpub.put("ChiaveDSA2048Pub", Base64.getEncoder().encodeToString(DSAKeys2048.getPublic().getEncoded()));
                jpriv.put("ChiaveDSA2048Priv", Base64.getEncoder().encodeToString(cipher.doFinal(DSAKeys2048.getPrivate().getEncoded())));
                pubKeychain.put(entry.getKey(), jpub.toString());
                privKeychain.put(entry.getKey(), jpriv.toString());
            } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchPaddingException | InvalidKeySpecException e) {
                e.printStackTrace();
                System.exit(1);
            }
        }
        PrintWriter pw1 = new PrintWriter(fileChiaviPubbliche);
        PrintWriter pw2 = new PrintWriter(fileChiaviPrivate);
        pw1.println(pubKeychain.toString());
        pw1.close();
        pw2.println(privKeychain.toString());
        pw2.close();
    }
    
    
    public static PrivateKey decryptFromPass(char[] password, byte[] data, String tipoChiave) throws IOException, BadPaddingException{
        /*Decifra con AES 128 bit il file il cui percorso è passato come parametro, sovrascrivendolo.
        utilizza una password per generare la chiave di decifratura. Ritorna i byte del file decrittato.
        */
        PrivateKey plain = null;
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec keySpec = new PBEKeySpec(password, salt, 65536, 128);
            SecretKey tmp = factory.generateSecret(keySpec);
            SecretKey secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
            Cipher cipher = Cipher.getInstance("AES/CFB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
            plain = KeyFactory.getInstance(tipoChiave).generatePrivate(new PKCS8EncodedKeySpec(cipher.doFinal(data)));
	} catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | InvalidAlgorithmParameterException e ) {
            e.printStackTrace();
            System.exit(1);
	}
        return plain;
    }
}
