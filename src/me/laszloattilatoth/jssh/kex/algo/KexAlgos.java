package me.laszloattilatoth.jssh.kex.algo;

import me.laszloattilatoth.jssh.proxy.Name;
import me.laszloattilatoth.jssh.proxy.NameWithId;

import java.util.HashMap;
import java.util.Map;

public class KexAlgos {
    private static final Map<Integer, KexAlgo> list = new HashMap<>();

    public static KexAlgo getById(int nameId) {
        return list.get(nameId);
    }

    public static KexAlgo getByName(String name) {
        for (KexAlgo c : list.values()) {
            if (c.name().equals(name)) {
                return c;
            }
        }

        return null;
    }

    public static KexAlgo getByNameWithId(NameWithId nameWithId) {
        return getById(nameWithId.getNameId());
    }

    static {
        put("diffie-hellman-group1-sha1", KexAlgo.Digest.SHA1);
        put("diffie-hellman-group14-sha1", KexAlgo.Digest.SHA1);
    }

    private static void put(String name, KexAlgo.Digest digest) {
        int nameId = Name.getNameId(name);
        list.put(nameId, new KexAlgo(name, nameId, digest));
    }
}
