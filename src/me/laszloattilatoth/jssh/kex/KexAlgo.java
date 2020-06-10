package me.laszloattilatoth.jssh.kex;

import me.laszloattilatoth.jssh.kex.algo.Cipher;

public class KexAlgo {
    private final Cipher cipher;

    public KexAlgo(Cipher cipher) {
        this.cipher = cipher;
    }

    public void encrypt() {}

    public void decrypt() {}
}
