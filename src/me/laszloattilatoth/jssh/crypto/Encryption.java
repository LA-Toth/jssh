package me.laszloattilatoth.jssh.crypto;

import me.laszloattilatoth.jssh.kex.algo.Cipher;

public class Encryption {
    private final Cipher cipher;

    public Encryption(Cipher cipher) {
        this.cipher = cipher;
    }

    public void encrypt() {}

    public void decrypt() {}
}
