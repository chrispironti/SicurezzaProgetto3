/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sicurezza_progetto_3;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import org.json.JSONObject;
import org.json.JSONArray;


/**
 * Il compito di questa classe è generare le richieste di Timestamp da inoltrare
 * al server TSA, ricevere i messaggi corrispondenti e verificarne la validità.
 * Viene generato l'hash associato al messaggio dell'utente i, si allega il suo ID,
 * viene firmato il tutto e poi cifrato.
 * Il server TSA genera il timestamp, lo firma e cifra la risposta. Una volta ricevuta viene valutata
 * la validità della firma apposta dal TSA, vengono usate le informazioni contenute
 * nel timestamp per controllare HV e SHV con il proprio hash, e infine viene firmato
 * il timestamp stesso, in maniera tale da proteggersi nel caso di scadenza di esso.
 * 
 * Supponiamo che in ogni timeframe inviamo al server una Map di richieste che deve gestire
 * tutte. Ogni elemento della Map è una stringa cifrata di un JSONObject contenente:
 * 1)IDUtente
 * 2)Hash del messaggio
 * 2)Algoritmo di firma
 * 3)Firma 
 * Lui ci risponde con una Map di risposte di cui dobbiamo verificare la validità.
 */

public class TimestampManager {
    
    private final String hashAlgorithm = "SHA-256";
    private int requestsNumber; //Numero di richieste nel Time Frame i
    private int IDNumber; //Inizializzato a 0, lo incrementiamo per ogni utente che fa le richieste
    private TSA TSAServer; //TSA Server
    private ArrayList<TSAMessage> requests;
    private ArrayList<TSAMessage> responses;
    private ArrayList<String> nomiFile;
    
    public TimestampManager(TSA TSAServer){
        this.TSAServer = TSAServer;
        this.requestsNumber = 0;
        this.IDNumber = 0;
        this.requests = new ArrayList<>();
        this.responses = new ArrayList<>();
        this.nomiFile = new ArrayList<>();
    }
    

    /*Il metodo riceve un oggetto utente e il messaggio a cui vuole apporre la 
    marca temporale. Il metodo genera l'hash di message e passa l'hash e 
    l'oggetto User al costruttore di TSARequest. 
    In TSARequest vengono inseriti in un JSONObject il quale viene firmato e cifrato. 
    La TSARequest viene poi inserita nella map come chiave l'id dell'utente e come
    valore l'oggetto TSARequest. Se un utente richiede più di una marca, le TSARequest
    vengono salvate in un array. Se il numero di richieste ha raggiunto il numero
    massimo consentito (8) chiama sendRequests.
    */
    public void generateRequest(String keychainFile, String userID, char[] password, String documentFile) throws IOException{
        requestsNumber += 1;
        
        //Ottengo la chiave privata Dsa dell'user dal keyring
        Keychain userKeyChain = new Keychain(keychainFile, password);
        PrivateKey dsaPrivKeyUser = userKeyChain.getPrivateKey("Key/DSA/2048/Main");
        //Ottengo la chiave pubblica Rsa della TSA dal file di chiavi pubbliche
        PublicKey rsaPubKeyTsa = PublicKeysManager.getPublicKeysManager().getPublicKey("TSA", "Key/RSA/1024/Main");
        //Creo il Json con User Id e msgDigest
        JSONObject j = new JSONObject();
        j.put("ID", userID);
        j.put("MD", Base64.getEncoder().encodeToString(computeFileDigest(documentFile)));
        TSAMessage req=null;
        /*
        //Da decommentare per testare una richiesta non valida in un lotto di richieste
        if(requestsNumber==5){
        SecureRandom random = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(2048,random);
        KeyPair DSAKeys = keyPairGenerator.generateKeyPair();
        req = new TSAMessage(j, DSAKeys.getPrivate(), rsaPubKeyTsa, "UserToTSA");
        }else*/
        req = new TSAMessage(j, dsaPrivKeyUser, rsaPubKeyTsa);

        //Aggiunge la richiesta all'ArrayList
        requests.add(req);
        this.nomiFile.add(documentFile);
        if (requestsNumber == 8){
            this.processRequests();
        }
    }
    
    private byte[] computeFileDigest(String documentFile) throws IOException{
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance(this.hashAlgorithm);
        } catch (NoSuchAlgorithmException ex) {
            System.out.println("Algoritmo non supportato");
        }
        BufferedInputStream is = new BufferedInputStream(new FileInputStream(documentFile));
        DigestInputStream dis = new DigestInputStream(is, md);
        while (dis.read() != -1){};
        byte[] msgDigest = md.digest();
        return msgDigest;
    }
    
    /*Manda la map di richieste al server TSA e salva le risposte nella mappa
    corrispondente della classe. Può essere chiamato in un qualunque momento dall'utente
    o automaticamente da generateRequest quando il numero max di richieste è stato raggiunto.
    */
    public void processRequests() throws IOException{ 
        responses=TSAServer.generateTimestamp(requests);      
        processResponses();
        this.requestsNumber = 0;
        this.requests = new ArrayList<>();
        this.responses= new ArrayList<>();
        this.nomiFile= new ArrayList<>();
    }

    /*
    Lancia un'eccezione per l utente i-esimo se 
    la sua marca non è verificata*/ 
    /*Attenzione usa lista nomi file per salvarli*/
    public void processResponses() throws IOException{
        
        PublicKey dsapublickey = PublicKeysManager.getPublicKeysManager().getPublicKey("TSA", "Key/DSA/2048/Main");
        Iterator<String> i = this.nomiFile.iterator();
        BufferedOutputStream bos = null;
        for(TSAMessage m: this.responses){
            String file = i.next();
            if (m != null){
                try {
                    byteUtils.verifyText(m.getInfo(), m.getSign(), dsapublickey);
                    bos = new BufferedOutputStream(new FileOutputStream("marche/"+file.split("/")[1]+".marca"));
                    bos.write(m.getInfo());
                } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | NotVerifiedSignException ex) {
                    System.out.println("Errore di firma per la marca associata al file: " +
                            file + ". La marca non verrà salvata.");
                }finally{
                    if (bos != null)
                        bos.close();
                }
            }
        }
    }
        
    public boolean verifyOffline(String docFile, String marcaFile) throws IOException{    
        JSONObject marca = readStamp(marcaFile);
        boolean verified = true;
        if(verifyInitialTimestamp(docFile, marca.getString("TS"), marca.getString("TSAD"))){
            String[] info = marca.getString("VI").split(",");
            MessageDigest md = null;
            try {
                md = MessageDigest.getInstance(this.hashAlgorithm);
            } catch (NoSuchAlgorithmException ex) {
                ex.printStackTrace();
                System.exit(1);
            }
            int i = 0;
            byte[] result = Base64.getDecoder().decode(marca.getString("TSAD"));
            byte[] next = null;
            while(i < info.length){
                next = Base64.getDecoder().decode(info[i]);
                i += 1;
                if(info[i].compareTo("s") == 0)
                    md.update(byteUtils.arrayConcat(next, result));
                else
                    md.update(byteUtils.arrayConcat(result, next));
                result = md.digest();
                i += 1;          
            }
            if(Base64.getEncoder().encodeToString(result).compareTo(marca.getString("HV")) != 0)
                verified = false;
        }else
            verified = false;
        return verified;
    }
         
/*    public boolean verifyOnline(String docFile, String marcaFile, String hashFile) throws IOException, NoSuchAlgorithmException{
        JSONObject marca = readStamp(marcaFile);
        boolean verified = true;
        if(verifyInitialTimestamp(docFile, marca.getString("TS"), marca.getString("TSAD"))){
            JSONObject hashValues = readHashValues(hashFile, marca.getInt("TF"));
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] shv_before = Base64.getDecoder().decode(hashValues.getString("SHVBefore"));
            byte[] hv_i = Base64.getDecoder().decode(marca.getString("HV"));
            md.update(byteUtils.arrayConcat(shv_before, hv_i));
            if(hashValues.getString("SHVActual").compareTo(Base64.getEncoder().encodeToString(md.digest())) != 0)
                verified = false;
        }
        else
            verified = false;
        return verified;        
    }*/
    
    public boolean verifyOnline(String docFile, String marcaFile, String hashFile, int limit) throws IOException{
        boolean verified=true;
        JSONObject j;
        JSONObject marca = readStamp(marcaFile);
        if(verifyInitialTimestamp(docFile, marca.getString("TS"), marca.getString("TSAD"))){
            int timeframe=marca.getInt("TF");
            JSONArray ja= readHashValues(hashFile);
            MessageDigest md = null;
            try {
                md = MessageDigest.getInstance(this.hashAlgorithm);
            } catch (NoSuchAlgorithmException ex) {
                ex.printStackTrace();
                System.exit(1);
            }
            limit = timeframe - limit;
            if(limit < 0)
                limit = 0;
            for(int i=1;i<=limit;i++){
                j=ja.getJSONObject(i);
                byte[] shv_before = Base64.getDecoder().decode(ja.getJSONObject(i-1).getString("SuperHashValue"));
                byte[] hv_i = Base64.getDecoder().decode(j.getString("HashValue"));
                md.update(byteUtils.arrayConcat(shv_before, hv_i));
                if(j.getString("SuperHashValue").compareTo(Base64.getEncoder().encodeToString(md.digest())) != 0)
                    verified = false;
            }
        }else{
            verified=false;
        }
        return verified;
    }
    
    private JSONObject readStamp(String marcaFile) throws IOException{
        byte[] encoded = Files.readAllBytes(Paths.get(marcaFile));
        return new JSONObject(new String(encoded, "UTF8"));
    }
    
    /*private JSONObject readHashValues(String hashFile, int timeframe) throws IOException{
        JSONArray hashes = new JSONArray(new String(Files.readAllBytes(Paths.get(hashFile)),"UTF-8"));
        JSONObject info = new JSONObject();
        info.put("SHVBefore", hashes.getJSONObject(timeframe-1).getString("SuperHashValue"));
        info.put("SHVActual", hashes.getJSONObject(timeframe).getString("SuperHashValue"));
        return info;
    }*/
    
     private JSONArray readHashValues(String hashFile) throws IOException{
        return new JSONArray(new String(Files.readAllBytes(Paths.get(hashFile)),"UTF-8"));
    }
    
    private boolean verifyInitialTimestamp(String docFile, String timeStamp, String TSADigest) throws IOException{
        byte[] docDigest = computeFileDigest(docFile);
        byte[] timestamp = timeStamp.getBytes("UTF8");
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance(this.hashAlgorithm);
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
            System.exit(1);
        }
        md.update(byteUtils.arrayConcat(docDigest, timestamp));
        String computedDigest = Base64.getEncoder().encodeToString(md.digest());
        return computedDigest.compareTo(TSADigest) == 0;        
    }
}
