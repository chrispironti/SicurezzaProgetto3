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
   
    /*
    TSARequest
    Riceve l'oggetto user e l'oggetto JSON contente id utente e hash message. 
    Lo converte in byte, lo firma 
    usando la propria chiave DSA privata, lo cifra con la chiave RSA pubblica 
    del server TSA, e lo converte in stringa mettendolo nel campo info .
    */
    public TSAMessage(JSONObject j, PrivateKey dsaPrivKey, PublicKey rsaPublicKey, String direction) throws IOException, BadPaddingException{
        //Costruisco il Json e ottengo i byte
        byte[] jBytes = byteFromJson(j);
        //Se trasmetto verso il server TSA firmo il plaintext
        if(direction.compareTo("UserToTSA") == 0){
            signText(jBytes, dsaPrivKey);
            encryptText(jBytes, rsaPublicKey);
            
        }
        //Se trasmetto verso l'utente cifro il ciphertext. 
        if(direction.compareTo("TSAToUser") == 0){
            encryptText(jBytes, rsaPublicKey);
            signText(this.info, dsaPrivKey);
        }
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

    public byte[] getInfo() {
        return info;
    }

    public byte[] getSign() {
        return sign;
    }
}
