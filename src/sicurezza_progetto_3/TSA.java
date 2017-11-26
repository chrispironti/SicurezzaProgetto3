/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sicurezza_progetto_3;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.*;
import java.sql.Timestamp;
import java.security.*;
import javax.crypto.*;
import org.json.*;

/**
 * Implementa i meccanismi per accettare e rispondere a richieste di Timestamp.
 * Il server TSA, una volta ricevuta la richiesta di timestamp dall'utente i deve
 * verificare la validità del messaggio ricevuto firmato usando la chiave di firma pubblica
 * del dato utente, poi deve generare la risposta contenente:
 * 1)La marca temporale;
 * 2)ID mittente e numero di serie della marca temporale;
 * 3)Il digest ricevuto h(D)
 * 4)Il digest H(h(D))) calcolato sul digest ricevuto (e lo cifra EVENTUALMENTE usando la chiave pubblica RSA del destinatario);
 * Il server TSA calcola il Merkel Tree nel timeframe i e pubblica HV(i). Calcola
 * e pubblica anche SHV(i) ottenuto come H(SHV(i-1)||HV(i)), ma è necessario SHV(0) 
 * (lo possiamo generare a caso). Usiamo due array di byte per rendere "pubblici"
 * gli HV e i SHV. Allo stesso modo usiamo un vettore di MerkelTree per memorizzare
 * gli alberi generati in ogni TimeFrame.
 * Il server TSA firma infine la marca temporale e allega:
 * 5)La firma stessa e il tipo di algoritmo di firma
 */
public class TSA {
    private int serialNumber;
    private int timeframe;
    //MerkelTree per il timeframe i-esimo
    private MerkleTree mt; 
    //Pubblichiamo i valori di HV e SHV a ogni timeframe
    private JSONArray hashValues;
    private Keychain TSAKeyChain;
    private MessageDigest md;
    public final int DUMMYSIZE = 10;

    
    public TSA() throws NoSuchAlgorithmException, IOException{
        this.serialNumber = 0;
        this.timeframe = 0;
        this.hashValues = new JSONArray();
        this.TSAKeyChain = new Keychain("TSAKeyChain","TSAPassword".toCharArray());
        this.md = MessageDigest.getInstance("SHA-256");
        computeHashValues();
    }
    
    
    /*Il metodo riceve l'array di richieste a cui apporre il timestamp. Per ogni richiesta,
    decifra il contenuto (con la propria chiave privata RSA), verifica la firma (con la chiave pubblica DSA dell'utente),
    calcola il time stamp, calcola H(h(D)). Costruisce poi il MerkelTree e mette
    in rootHash[timeframe] HV e in superRootHash[timeframe] SHV. Per ciascuna 
    risposta valuta le informazioni da dare per poter consentire all'utente di 
    verificare se HV e SHV sono corretti. Mette infine tutte queste informazioni in un JSONObject
    da passare al costruttore di TSAResponse. In particolare:
    1)Timestamp t (TimeStamp);
    2)userID (String);
    3)serialNumber (int);
    4)originalMessageDigest (byte[]);
    5)TSADigest (byte[]);
    6)verifyInformation (è un ArrayList di ArrayList, ciascuno contenente 3 tuple);
    In TSAResponse il JSONObect viene convertito in stringa, firmato con la propria
    chiave privata DSA e cifrato con la chiave RSA pubblica dell'utente.
    Se il numero di richieste è inferiore a 8 il metodo deve inserire nel Merkel
    Tree i nodi rimanenti con hash fittizi.*/
    
    public ArrayList<TSAMessage> generateTimestamp(ArrayList<TSAMessage> requests) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, BadPaddingException{
        
        this.mt = new MerkleTree();
        this.timeframe += 1;
        JSONObject j = new JSONObject();
        ArrayList<JSONObject> partialResponses = createResponses(requests);
        computeHashValues();
        ArrayList<String> merkleInfo = mt.buildInfo();
        saveHashValues();
        return finalizeResponses(partialResponses, merkleInfo);
        
    }
    
    private JSONObject makeResponseInfo(JSONObject userInfo){  
        
        JSONObject responseInfo = new JSONObject();
        String t = new Timestamp(System.currentTimeMillis()+10000).toString(); 
        responseInfo.put("TimeStamp", t);
        responseInfo.put("UserID", userInfo.getString("UserID"));
        responseInfo.put("SerialNumber", this.serialNumber);
        String messageDigest = userInfo.getString("MessageDigest");
        responseInfo.put("MessageDigest",messageDigest);
        byte[] userMessageDigest = Base64.getDecoder().decode(messageDigest);
        byte[] timestamp = Base64.getDecoder().decode(t);
        this.mt.insert(userMessageDigest, timestamp);
        this.md.update(byteUtils.arrayConcat(userMessageDigest, timestamp));
        responseInfo.put("TSADigest",Base64.getEncoder().encodeToString(this.md.digest()));
        responseInfo.put("TimeFrame", this.timeframe);
        return responseInfo;
    }
    
    private ArrayList<JSONObject> createResponses(ArrayList<TSAMessage> requests) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IOException, BadPaddingException{
        
        PrivateKey rsaprivKey = this.TSAKeyChain.getPrivateKey("Key/RSA/2048/Main");
        ArrayList<JSONObject> partialResponses = new ArrayList<>();
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding");
        c.init(Cipher.DECRYPT_MODE, rsaprivKey);
        int requestNumber = 0;
        /*Esamino le richieste, decifro, verifico la firma e creo i JSONObject di risposta
        da completare con le informazioni derivanti dalla costruzione del Merkel Tree
        */
        for(TSAMessage m: requests){          
                try{
                    this.serialNumber += 1;
                    byte[] decrypted = c.doFinal(m.getInfo());
                    JSONObject userInfo = new JSONObject(new String(decrypted,"UTF8"));
                    PublicKey dsapubKey = PublicKeysManager.getPublicKeysManager().getPublicKey(userInfo.getString("UserID"), "Key/DSA/2048/Main");
                    byteUtils.verifyText(decrypted, m.getSign(), dsapubKey);
                    JSONObject responseInfo = makeResponseInfo(userInfo);
                    partialResponses.add(responseInfo);
                    requestNumber += 1;
                } catch (IllegalBlockSizeException | BadPaddingException | SignatureException | UnsupportedEncodingException | NotVerifiedSignException | NoSuchAlgorithmException | InvalidKeyException ex) {
                    System.out.println("Errore. Impossibile processare richiesta numero: " + requestNumber + 
                            "del timeframe attuale. La richiesta verrà ignorata.");
                    partialResponses.add(null);
            }
        }
        /*Se ci sono meno di 8 richieste (ne sono arrivate meno di 8 o alcune sono
        state scartate), completa il merkel tree con nodi fittizi
        poi calcola HV e le info per ciascun utente. */
        Random r = new Random();
        while (requestNumber < 8){
            byte[] dummy = new byte[this.DUMMYSIZE];
            r.nextBytes(dummy);
            this.md.update(dummy);
            String t = new Timestamp(System.currentTimeMillis()+10000).toString();
            this.mt.insert(this.md.digest(), Base64.getDecoder().decode(t));
            requestNumber += 1;
        }
        return partialResponses;
    }
    
    private ArrayList<TSAMessage> finalizeResponses(ArrayList<JSONObject> partialResponses, ArrayList<String> merkleInfo) throws IOException, BadPaddingException{
        
        Iterator<String> i = merkleInfo.iterator();
        ArrayList<TSAMessage> responses = new ArrayList<>();
            for(JSONObject j: partialResponses){
                if (j != null){
                    j.put("VerificationInfo", i.next());
                    j.put("HashValue", getHashValue(this.timeframe));
                    PublicKey rsapubkey = PublicKeysManager.getPublicKeysManager().getPublicKey(j.getString("UserID"),"Key/RSA/2048/Main");
                    PrivateKey dsaprivkey = this.TSAKeyChain.getPrivateKey("Key/RSA/2048/Main");
                    responses.add(new TSAMessage(j, dsaprivkey , rsapubkey, "TSAToUser"));
                }else{
                    responses.add(null);
                }
            }           
        return responses;
    }
    
    private void computeHashValues() throws NoSuchAlgorithmException{
        
        byte[] shv_i = null;
        JSONObject j = new JSONObject();
        if (this.timeframe == 0){
            Random r = new Random();
            shv_i = new byte[this.DUMMYSIZE];
            r.nextBytes(shv_i);
        }else{
            byte[] hv = mt.buildMerkleTree();
            String superHashValue = this.hashValues.getJSONObject(this.timeframe-1).getString("SuperHashValue");
            byte[] shv_before = Base64.getDecoder().decode(superHashValue);
            shv_i = byteUtils.arrayConcat(shv_before, hv);
            j.put("HashValue", Base64.getEncoder().encodeToString(hv));
        }            
        this.md.update(shv_i);
        j.put("SuperHashValue", Base64.getEncoder().encodeToString(this.md.digest()));
        this.hashValues.put(this.timeframe, j);
    }
    
    public String getHashValue(int timeframe){
        
        if (timeframe == 0){
            System.out.println("Errore. Nessun Hash Value al timeframe 0.");
            return null;
        }
        else{
            JSONObject j = this.hashValues.getJSONObject(timeframe);
            return j.getString("HashValue");
        }
    }
    
    public String getSuperHashValue(int timeframe){
        
        JSONObject j = this.hashValues.getJSONObject(timeframe);
        return j.getString("SuperHashValue");
    }   
    
    
    private void saveHashValues() throws IOException{
        
            BufferedWriter bw = null;
        try{
            bw = new BufferedWriter( new FileWriter("hashValues"));
            bw.write(this.hashValues.toString());
        }finally{
            bw.close();
        }
    }
}
