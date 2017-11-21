/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sicurezza_progetto_3;
import java.security.*;
import javax.crypto.*;

/**
 * Potrebbe servirci. Ancora, possiamo usare JSON volendo.
 * 
 */
public class User {
    private String ID;
    private byte[] password;
    private byte[] salt;
    private PrivateKey DSAPrivateKey;
    private PrivateKey RSAPrivateKey;

    public User(byte[] password, String KeychainFile) {
        this.password = password;
    }

    public String getID() {
        return ID;
    }

    public byte[] getPassword() {
        return password;
    }

    public byte[] getSalt() {
        return salt;
    }

    public PrivateKey getDSAPrivateKey() {
        return DSAPrivateKey;
    }

    public PrivateKey getRSAPrivateKey() {
        return RSAPrivateKey;
    }
    
    
    
}
