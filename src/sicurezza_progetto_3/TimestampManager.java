/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sicurezza_progetto_3;
import java.io.*;
import java.security.*;
import javax.crypto.*;
import java.util.*;
import org.json.JSONObject;


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
    
    private int requestsNumber; //Numero di richieste nel Time Frame i
    private int IDNumber; //Inizializzato a 0, lo incrementiamo per ogni utente che fa le richieste
    private TSA TSAServer; //TSA Server
    private ArrayList<TSAMessage> requests;
    private ArrayList<TSAMessage> responses;
    private ArrayList<String> nomiFiles;
    
    public TimestampManager(TSA TSAServer){
        this.TSAServer = TSAServer;
        this.requestsNumber = 0;
        this.IDNumber = 0;
        this.requests = null;
        this.responses = null;
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
    //Bisogna passare anche il file delle chiavi pubbliche per la chiave pub rsa?
    public void generateRequest(String keychainFile, String fileChiaviPubbliche, String userId, char[] password, String documentFile) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, BadPaddingException, UnsupportedEncodingException, SignatureException{
        requestsNumber += 1;
        
        //Ottengo la chiave privata Dsa dal keyring
        Keychain kc = new Keychain(keychainFile, password);
        PrivateKey dsaPrivKey = kc.getPrivateKey(userId);
        //Ottengo la chiave pubblica Rsa dal file di chiavi pubbliche
        
        //Calcolo digest del messaggio con digestinputstream
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException ex) {
            System.out.println("Algoritmo non supportato");
        }
        md.update(message);
        byte[] msgDigest = md.digest();
        
        //Creo il Json con User Id e msgDigest
        JSONObject j = new JSONObject();
        j.put("userID", userId);
        j.put("msgDigest", msgDigest);
        
        //Crea la richiesta
        TSAMessage req = new TSAMessage(j, dsaPrivKey, rsaPublicKey);
        
        //Aggiunge la richiesta all'ArrayList
        if(requests==null){
            requests = new ArrayList<>();   
        }
        requests.add(req);

        if (requestsNumber == 8){
            this.processRequests();
        }   
        
//        Operazioni sulla map
//        Controllo nella map delle richieste
//        Se l'user ha già delle richieste aggiunge la richiesta nell'ArrayList
//        if(requests.containsKey(user.getID())){
//            requests.get(user.getID()).add(req);
//        }
//        else{ //Altrimenti crea un ArrayList con la richiesta dell'utente
//            ArrayList<TSARequest> reqList = new ArrayList<>();
//            reqList.add(req);
//            requests.put(user.getID(), reqList);
//        }
    }
    
    /*Manda la map di richieste al server TSA e salva le risposte nella mappa
    corrispondente della classe. Può essere chiamato in un qualunque momento dall'utente
    o automaticamente da generateRequest quando il numero max di richieste è stato raggiunto.
    */
    public void processRequests() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, BadPaddingException, UnsupportedEncodingException, SignatureException{ 
        responses=TSAServer.generateTimestamp(requests);      
        //chiama un metodo che verifica, decifra e salva rispos
        processResponses();
        this.requestsNumber = 0;
        this.requests = new ArrayList<>();
    }

    /*
    Lancia un'eccezione per l utente i-esimo se 
    la sua marca non è verificata*/ 
    /*Attenzione usa lista nomi file per salvarli*/
    public void processResponses() throws UnsupportedEncodingException, IOException, InvalidKeyException, SignatureException{
        for (TSAMessage r: this.responses){
            //Verifica della firma
            Signature dsa = null;
            try {
                dsa = Signature.getInstance("SHA256withDSA");
            } catch (NoSuchAlgorithmException ex) {
                System.out.println("Algoritmo non supportato");
            }
            dsa.initVerify(); //TSA Public Key
            dsa.update(r.getInfo());  //r.info.getBytes?
            Boolean verified=false;
            try {
                verified = dsa.verify(r.getSign());
            } catch (SignatureException ex) {
                System.out.println("Errore nella verifica della firma");
            }
        }
        //Decifratura RSA private key
        //Dovrei sapere chi è l'user
        //Key ring e file chiavi pubbliche come attributi?
    }
        
    public boolean verifyOffline(String docFile, String marcaFile){    
    
    }
         
    public boolean verifyOnline(String docFile, String marcaFile, String hashFile){
        
    }
}
