/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sicurezza_progetto_3;
import java.io.*;
import java.security.*;
import java.util.*;
import org.json.JSONObject;
import org.json.JSONArray;


/**
 * Il compito di questa classe è generare le richieste di Timestamp da inoltrare
 * al server TSA, ricevere i messaggi corrispondenti e verificarne la validità.
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
    
    public void generateRequest(String keychainFile, String userID, char[] password, String documentFile) throws IOException{
        
        requestsNumber += 1;
        
        //Ottengo la chiave privata Dsa dell'user dal keyring
        Keychain userKeyChain = new Keychain(keychainFile, password);
        PrivateKey dsaPrivKeyUser = userKeyChain.getPrivateKey("Key/DSA/2048/Main");
        //Ottengo la chiave pubblica Rsa della TSA dal file di chiavi pubbliche
        PublicKey rsaPubKeyTsa = PublicKeysManager.getPublicKeysManager().getPublicKey("TSA", "Key/RSA/2048/Main");
        //Creo il Json con User Id e msgDigest
        JSONObject j = new JSONObject();
        j.put("ID", userID);
        j.put("MD", Base64.getEncoder().encodeToString(computeFileDigest(documentFile)));
        //Da decommentare per testare situazioni in cui una richiesta non è 
        //valida e non viene processata da TSA
        /*if(this.requests.size() == 2){    
            KeyPairGenerator keyPairGenerator = null;
            try {
                keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            } catch (NoSuchAlgorithmException ex) {
                System.out.println("Errore, algoritmo non supportato");
            }
            keyPairGenerator.initialize(2048, new SecureRandom());
            KeyPair falseKeys = keyPairGenerator.generateKeyPair();
            rsaPubKeyTsa = falseKeys.getPublic();
        }*/
        TSAMessage req = new TSAMessage(j, dsaPrivKeyUser, rsaPubKeyTsa);
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
    
    public void processRequests() throws IOException{ 
        
        responses=TSAServer.generateTimestamp(requests);      
        processResponses();
        this.requestsNumber = 0;
        this.requests = new ArrayList<>();
        this.responses= new ArrayList<>();
        this.nomiFile= new ArrayList<>();
    }

    public void processResponses() throws IOException{
        
        PublicKey dsapublickey = PublicKeysManager.getPublicKeysManager().getPublicKey("TSA", "Key/DSA/2048/Main");
        Iterator<String> i = this.nomiFile.iterator();
        BufferedOutputStream bos = null;
        for(TSAMessage m: this.responses){
            String file = i.next();
            if (m != null){
                try {
                    DTSUtils.verifyText(m.getInfo(), m.getSign(), dsapublickey);
                    JSONObject j = new JSONObject(new String(m.getInfo(),"UTF8"));
                    j.put("TSASign", Base64.getEncoder().encodeToString(m.getSign()));
                    String[] newPath = file.split("/");
                    bos = new BufferedOutputStream(new FileOutputStream("marche/"+newPath[newPath.length -1]+".marca"));
                    bos.write(j.toString().getBytes("UTF8"));
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
        
        JSONObject marca = DTSUtils.readStamp(marcaFile);
        boolean verified = false;
        /*Controllo che l'hash del documento, concatenato al timestamp
        sia effettivamente uguale al digest calcolato dalla TSA*/
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
                    md.update(DTSUtils.arrayConcat(next, result));
                else
                    md.update(DTSUtils.arrayConcat(result, next));
                result = md.digest();
                i += 1;          
            }
            /*Se l'HV calcolato coincide con quello contenuto nella marca allora la verifica
            è andata a buon fine*/
            if(Base64.getEncoder().encodeToString(result).compareTo(marca.getString("HV")) == 0)
                verified = true;
        }
        return verified;
    }
           
    public boolean verifyOnline(String docFile, String marcaFile, String hashFile, int limit) throws IOException{
        
        boolean verified = false;
        JSONObject j;
        JSONObject marca = DTSUtils.readStamp(marcaFile);
        /*Controllo che l'hash del documento, concatenato al timestamp
        sia effettivamente uguale al digest calcolato dalla TSA*/
        if(verifyInitialTimestamp(docFile, marca.getString("TS"), marca.getString("TSAD"))){
            int timeframe=marca.getInt("TF");
            JSONArray ja= DTSUtils.readHashValues(hashFile);
            MessageDigest md = null;
            try {
                md = MessageDigest.getInstance(this.hashAlgorithm);
            } catch (NoSuchAlgorithmException ex) {
                ex.printStackTrace();
                System.exit(1);
            }
            limit = timeframe - limit;
            if(limit < 0)
                limit = 1;
            byte[] hv_i = null;
            byte[] shv_before = null;
            for(int i=limit;i<=timeframe;i++){
                j=ja.getJSONObject(i);
                shv_before = Base64.getDecoder().decode(ja.getJSONObject(i-1).getString("SuperHashValue"));
                hv_i = Base64.getDecoder().decode(j.getString("HashValue"));
                md.update(DTSUtils.arrayConcat(shv_before, hv_i));
                if(j.getString("SuperHashValue").compareTo(Base64.getEncoder().encodeToString(md.digest())) != 0)
                    return false; //Se un elemento della catena non è valido, ritorna immediatamente false
            }
            if(Base64.getEncoder().encodeToString(hv_i).compareTo(marca.getString("HV")) == 0)
                /*Se HV(timeframe) coincide con l'HV contenuto nella marca ricevuta,
                allora la verifica è andata a buon fine*/
                verified = true; 
        }
        return verified;
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
        md.update(DTSUtils.arrayConcat(docDigest, timestamp));
        String computedDigest = Base64.getEncoder().encodeToString(md.digest());
        return computedDigest.compareTo(TSADigest) == 0;        
    }
    
    public boolean verifyTSASign(String marcaFile) throws IOException{
        
        JSONObject marca = DTSUtils.readStamp(marcaFile);
        byte[] sign = Base64.getDecoder().decode(marca.getString("TSASign")); 
        marca.remove("TSASign");
        PublicKey dsaPubKey = PublicKeysManager.getPublicKeysManager().getPublicKey("TSA", "Key/DSA/2048/Main");
        byte[] jBytes = null;
        try {
            jBytes = marca.toString().getBytes("UTF8");
            DTSUtils.verifyText(jBytes, sign, dsaPubKey);
        } catch (NoSuchAlgorithmException | NotVerifiedSignException | SignatureException | InvalidKeyException ex) {
            return false;
        } catch(UnsupportedEncodingException ex1){
            System.out.println("Errore, codifica non supportata.");
        }
        return true;
    }
}
