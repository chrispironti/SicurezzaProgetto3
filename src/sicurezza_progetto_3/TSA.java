/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sicurezza_progetto_3;
import java.util.*;
import java.sql.Timestamp;
import java.security.*;
import javax.crypto.*;

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

    private String hashAlgorithm; //Algoritmo di hash TSA. Supporta solo MD5 SHA1 e SHA256.
    private int serialNumber;
    private int timeframe;
    //MerkelTree per il timeframe i-esimo
    private MerkelTree mt; 
    //Pubblichiamo i valori di HV e SHV a ogni timeframe
    public ArrayList<byte[]> rootHash;
    public ArrayList<byte[]> superRootHash;
    //Chiave privata DSA del server TSA
    //Chiave privata RSA del server TSA
    
    public TSA(String hashAlgorithm){
        this.hashAlgorithm = hashAlgorithm;
        this.serialNumber = 0;
        this.timeframe = 0;
        this.rootHash = new ArrayList<>();
        this.superRootHash = new ArrayList<>();
    }
    
    public void newTimeFrame(){
        this.mt = new MerkelTree();
        this.timeframe += 1;
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
    
    public HashMap<String,TSAResponse> generateTimestamp(ArrayList<TSARequest> requests){
        
    }
}
