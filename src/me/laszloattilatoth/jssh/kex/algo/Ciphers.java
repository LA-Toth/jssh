package me.laszloattilatoth.jssh.kex.algo;

import me.laszloattilatoth.jssh.proxy.Name;
import me.laszloattilatoth.jssh.proxy.NameWithId;

import java.util.HashMap;
import java.util.Map;

public class Ciphers {
    private static final Map<Integer, Cipher> ciphers = new HashMap<>();

    public static Cipher getById(int nameId) {
        return ciphers.get(nameId);
    }

    public static Cipher getByName(String name) {
        for (Cipher c : ciphers.values()) {
            if (c.name().equals(name)) {
                return c;
            }
        }

        return null;
    }

    public static Cipher getByNameWithId(NameWithId nameWithId) {
        return getById(nameWithId.getNameId());
    }

    static {
        put("3des-cbc", 8, 24, 0, 0, Cipher.FLAG_3DES | Cipher.FLAG_CBC);
        put("aes128-cbc", 16, 16, 0, 0, Cipher.FLAG_AES | Cipher.FLAG_CBC);
        put("aes192-cbc", 16, 24, 0, 0, Cipher.FLAG_AES | Cipher.FLAG_CBC);
        put("aes256-cbc", 16, 32, 0, 0, Cipher.FLAG_AES | Cipher.FLAG_CBC);
        put("aes128-ctr", 16, 16, 0, 0, Cipher.FLAG_AES | Cipher.FLAG_AES_CTR);
        put("aes192-ctr", 16, 24, 0, 0, Cipher.FLAG_AES | Cipher.FLAG_AES_CTR);
        put("aes256-ctr", 16, 32, 0, 0, Cipher.FLAG_AES | Cipher.FLAG_AES_CTR);
    }

    private static void put(String name, long blockSize, long keyLen, long ivLen, long authLen, long flags) {
        int nameId = Name.getNameId(name);
        ciphers.put(nameId, new Cipher(name, nameId, blockSize, keyLen, ivLen != 0 ? ivLen : blockSize, authLen, flags));
    }
}
