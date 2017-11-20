/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sicurezza_progetto_3;

/**
 *
 * Classe tupla. Mi serve per costruire le informazioni da dare all'utente
 * per ricostruire l'hash value.
 */
public class Pair<S, T> {
    public final S x;
    public final T y;

    public Pair(S x, T y) { 
        this.x = x;
        this.y = y;
    }
}
