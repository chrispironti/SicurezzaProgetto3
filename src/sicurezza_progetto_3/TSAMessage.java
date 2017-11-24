/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sicurezza_progetto_3;

import java.io.*;
import org.json.JSONObject;
import java.security.*;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.*;

/**

 */
public class TSAMessage {
    private byte[] info;
    private byte[] sign;
   
    /*Riceve l'oggetto user e l'oggetto JSON contente id utente e hash message. 
    Lo converte in byte, lo firma 
    usando la propria chiave DSA privata, lo cifra con la chiave RSA pubblica 
    del server TSA, e lo converte in stringa mettendolo nel campo info .
    Attenzione ovviamente il message digest nel jsonobject è salvato con base64
    */
    public TSAMessage(JSONObject j, PrivateKey dsaPrivKey, PublicKey rsaPublicKey) throws IOException, BadPaddingException{
        //Costruisco il Json e ottengo i byte
        byte[] jBytes = byteFromJson(j);
        
        //Firma dei byte del Json con la chiave privata dell'user
        signText(jBytes, dsaPrivKey);
        
        //Cifratura con la chiave pubblica della TSA
        this.encryptText(jBytes, rsaPublicKey);
    }
    
    private byte[] byteFromJson(JSONObject j){  
        //Ottengo i byte dal Json
        byte[] jBytes = null;
        try {
            jBytes = j.toString().getBytes("UTF8");
        } catch (UnsupportedEncodingException ex) {
            System.out.println("Encoding non supportato");
        }
        
        return jBytes;
    }
    
    private void signText(byte[] plaintext, PrivateKey DSAPrKey){
        Signature dsa = null;
        try {    
            dsa = Signature.getInstance("SHA256withDSA");
            dsa.initSign(DSAPrKey);
            dsa.update(plaintext);
            sign = dsa.sign();
        } catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
    
    private void encryptText(byte[] plainText, PublicKey RSAPubKey){
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
            cipher.init(Cipher.ENCRYPT_MODE, RSAPubKey);
            info = cipher.doFinal(plainText);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
                e.printStackTrace();
                System.exit(1);
        }
    }
}
