/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sicurezza_progetto_3;
import java.sql.Timestamp;
import java.util.*;

/**
 * Risposta del server TSA.
 * 
 */
public class TSAResponse {

    public String info;
    public String signType;
    public byte[] sign;
    
    /*Riceve il JSONObject. Converte il JSON object in stringa, lo firma
    usando la propria chiave privata DSA e lo cifra usando la chiave RSA pubblica dell'user.
    */
    public TSAResponse(JSONObject j, String userID){

    }
}
