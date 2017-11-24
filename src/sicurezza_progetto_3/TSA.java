/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sicurezza_progetto_3;
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

    private final String hashAlgorithm = "SHA-256"; //Algoritmo di hash TSA, fissato a SHA-256.
    private int serialNumber;
    private int timeframe;
    //MerkelTree per il timeframe i-esimo
    private MerkleTree mt; 
    //Pubblichiamo i valori di HV e SHV a ogni timeframe
    private ArrayList<byte[]> rootHash;
    private ArrayList<byte[]> superRootHash;
    public final int DUMMYSIZE = 10;
    private 

    
    public TSA(char[] password, String keychainTSA, String keychainFilePub) throws NoSuchAlgorithmException, IOException{
        this.serialNumber = 0;
        this.timeframe = 0;
        this.rootHash = new ArrayList<>();
        this.superRootHash = new ArrayList<>();
        computeSuperHashValue();
        this.TSAUser = new User("TSA", password, keychainTSA, keychainFilePub);
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
        
        this.mt = new MerkleTree(this.hashAlgorithm);
        this.timeframe += 1;
        HashMap<String,ArrayList<JSONObject>> partialResponses = createResponses(requests);
        byte[] hashValue = mt.buildMerkleTree();
        this.rootHash.add(hashValue);
        computeSuperHashValue();
        ArrayList<String> merkleInfo = mt.buildInfo();
        saveHashValues();
        return finalizeResponses(partialResponses, merkleInfo);
        
    }
    
    private void verifyText(byte[] plaintext, byte[] firmaDSA, String tipofirma, PublicKey DSAKeyPub) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, NotVerifiedSignException{

        Signature dsa = Signature.getInstance(tipofirma);
        dsa.initVerify(DSAKeyPub);
        dsa.update(plaintext);
        if(!dsa.verify(firmaDSA))
            throw new NotVerifiedSignException();
}

    private JSONObject makeResponseInfo(JSONObject userInfo, MessageDigest md){  
        
        JSONObject responseInfo = new JSONObject();
        responseInfo.put("TimeStamp", new Timestamp(System.currentTimeMillis()));
        responseInfo.put("UserID", userInfo.getString("UserID"));
        responseInfo.put("SerialNumber", this.serialNumber);
        String messageDigest = userInfo.getString("MessageDigest");
        responseInfo.put("MessageDigest",messageDigest);
        byte[] userMessageDigest = Base64.getDecoder().decode(messageDigest);
        md.update(userMessageDigest);
        responseInfo.put("TSADigest",Base64.getEncoder().encodeToString(md.digest()));
        responseInfo.put("TimeFrame", this.timeframe);
        return responseInfo;
    }
    
    private HashMap<String,ArrayList<JSONObject>> createResponses(HashMap<String,ArrayList<TSARequest>> requests) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IOException, BadPaddingException{
        
        PrivateKey rsaprivKey = this.TSAUser.getRsaPrivKey();
        JSONObject pubKeys = KeychainUtils.getPubKeychain(keyChainFilePub);
        HashMap<String,ArrayList<JSONObject>> partialResponses = new HashMap<>();
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding");
        c.init(Cipher.DECRYPT_MODE, rsaprivKey);
        MessageDigest md = MessageDigest.getInstance(this.hashAlgorithm);
        int requestNumber = 0;
        /*Esamino le richieste, decifro, verifico la firma e creo i JSONObject di risposta
        da completare con le informazioni derivanti dalla costruzione del Merkel Tree
        */
        for(Map.Entry<String,ArrayList<TSARequest>> e: requests.entrySet()){
            ArrayList<JSONObject> objArray = new ArrayList<>();
            
            for(TSARequest req: e.getValue()){
                try{
                    this.serialNumber += 1;
                    byte[] decrypted = c.doFinal(req.info); //Da Aggiustare
                    verifyText(decrypted, req.sign, req.signType, dsapubkey);
                    JSONObject userInfo = new JSONObject(new String(decrypted,"UTF8"));
                    JSONObject responseInfo = makeResponseInfo(userInfo, md);
                    this.mt.insert(Base64.getDecoder().decode(userInfo.getString("MessageDigest")));
                    objArray.add(responseInfo);
                    requestNumber += 1;
                } catch (IllegalBlockSizeException | BadPaddingException | SignatureException | UnsupportedEncodingException | NotVerifiedSignException | NoSuchAlgorithmException | InvalidKeyException ex) {
                    System.out.println("Errore. Impossibile processare richiesta numero: " + requestNumber + 
                            "del timeframe attuale, da parte " 
                                    + "dell'utente: " + e.getKey()+". La richiesta verrà ignorata.");
                }
            }
            if(!objArray.isEmpty()){
                partialResponses.put(e.getKey(),objArray);
            }
        }
        /*Se ci sono meno di 8 richieste (ne sono arrivate meno di 8 o alcune sono
        state scartate), completa il merkel tree con nodi fittizi
        poi calcola HV e le info per ciascun utente. */
        Random r = new Random();
        while (requestNumber < 8){
            byte[] dummy = new byte[this.DUMMYSIZE];
            r.nextBytes(dummy);
            md.update(dummy);
            this.mt.insert(md.digest());
            requestNumber += 1;
        }
        return partialResponses;
    }
    
    private HashMap<String,ArrayList<TSAResponse>> finalizeResponses(HashMap<String,ArrayList<JSONObject>> partialResponses, ArrayList<String> merkleInfo){
        
        Iterator<String> i = merkleInfo.iterator();
        HashMap<String,ArrayList<TSAResponse>> responses = new HashMap<>();
        for(Map.Entry<String,ArrayList<JSONObject>> e: partialResponses.entrySet()){
            ArrayList<TSAResponse> value = new ArrayList<>();
            for(JSONObject j: e.getValue()){
                j.put("Verification Info", i.next());
                value.add(new TSAResponse(j,e.getKey()));
            }
            responses.put(e.getKey(), value);            
        }
        return responses;
    }
    
    private void computeSuperHashValue() throws NoSuchAlgorithmException{
        
        MessageDigest md = MessageDigest.getInstance(this.hashAlgorithm);
        byte[] shv_i = null;
        if (this.timeframe == 0){
            Random r = new Random();
            shv_i = new byte[this.DUMMYSIZE];
            r.nextBytes(shv_i);    
        }else
            shv_i = byteUtils.arrayConcat(this.superRootHash.get(this.timeframe - 1), 
            this.rootHash.get(this.timeframe));
        md.update(shv_i);
        this.superRootHash.add(md.digest());
    }
    
    public byte[] getHashValue(int timeframe){
        return this.rootHash.get(timeframe);
    }
    
    public byte[] getSuperHashValue(int timeframe){
        return this.superRootHash.get(timeframe);
    }   
    
    
    private void saveHashValues(){
        
    }
}
