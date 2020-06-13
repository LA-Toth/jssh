package me.laszloattilatoth.jssh.algo;

import me.laszloattilatoth.jssh.proxy.Name;
import me.laszloattilatoth.jssh.proxy.NameWithId;

import java.util.HashMap;
import java.util.Map;

public class KeyAlgos {
    private static final Map<Integer, KeyAlgo> list = new HashMap<>();

    public static KeyAlgo getById(int nameId) {
        return list.get(nameId);
    }

    public static KeyAlgo getByName(String name) {
        for (KeyAlgo c : list.values()) {
            if (c.name().equals(name)) {
                return c;
            }
        }

        return null;
    }

    public static KeyAlgo getByNameWithId(NameWithId nameWithId) {
        return getById(nameWithId.getNameId());
    }

    static {
        put("ssh-rsa");
        put("ssh-dss");
    }

    private static void put(String name) {
        int nameId = Name.getNameId(name);
        list.put(nameId, new KeyAlgo(name, nameId));
    }
}
