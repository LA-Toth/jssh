package me.laszloattilatoth.jssh.kex;

import me.laszloattilatoth.jssh.kex.algo.Cipher;
import me.laszloattilatoth.jssh.kex.algo.Ciphers;
import me.laszloattilatoth.jssh.kex.algo.Mac;
import me.laszloattilatoth.jssh.kex.algo.Macs;
import me.laszloattilatoth.jssh.proxy.NameWithId;

public class NewKeys {
    public Cipher enc;
    public Mac mac;

    public void setEncryption(NameWithId encAlg) {
        enc = Ciphers.getByNameWithId(encAlg);
    }

    public long cipherAuthLen() {
        return enc != null ? enc.authLen() : 0;
    }

    public void setMac(NameWithId macAlg) {
        mac = Macs.getByNameWithId(macAlg);
    }

    public void setCompression(NameWithId compAlg) {
        // not supported as of now
    }
}
