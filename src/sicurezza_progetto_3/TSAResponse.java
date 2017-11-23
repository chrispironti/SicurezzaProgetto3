/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sicurezza_progetto_3;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import org.json.*;

/**
 * Risposta del server TSA.
 * 
 */
public class TSAResponse {

    public byte[] info;
    public String signType;
    public byte[] sign;
    
    /*Riceve il JSONObject. Converte il JSON object in stringa, lo firma
    usando la propria chiave privata DSA e lo cifra usando la chiave RSA pubblica dell'user.
    */
    public TSAResponse(JSONObject j, User user, String signType) throws IOException{
        this.signType = signType;
        
        //Ottengo i byte dal Json
        byte[] jRespBytes = null;
        try {
            jRespBytes = j.toString().getBytes("UTF8");
        } catch (UnsupportedEncodingException ex) {
            System.out.println("Encoding non supportato");
        }
        
        //Firma dei byte del Json con la chiave privata della TSA
        //DSAKeyPr = TSAServer.getPublicKey?
        //signText(jRespBytes, DSAKeyPr);
        
        //Cifratura con la chiave pubblica dell'user
        PublicKey RSAPubKey = user.getRsaPubKey();
        this.encryptText(jRespBytes, RSAPubKey);

    }
    
    private void signText(byte[] plaintext, PrivateKey DSAKeyPr){
        Signature dsa = null;
        try {    
            dsa = Signature.getInstance(signType);
            dsa.initSign(DSAKeyPr);
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
