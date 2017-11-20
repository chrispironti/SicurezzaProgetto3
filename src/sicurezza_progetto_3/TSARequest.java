/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sicurezza_progetto_3;

/**

 */
public class TSARequest {
    public String info;
    public byte[] sign;
    public String signType;
    
    /*Riceve l'oggetto user e l'oggetto JSON contente id utente e hash message. 
    Lo converte in byte, lo firma 
    usando la propria chiave DSA privata, lo cifra con la chiave RSA pubblica 
    del server TSA, e lo converte in stringa mettendolo nel campo info    
    */
    public TSARequest(User user, JSONObject j){
        
    }
}
