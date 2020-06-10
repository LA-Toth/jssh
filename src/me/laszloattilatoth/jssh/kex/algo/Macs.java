package me.laszloattilatoth.jssh.kex.algo;

import me.laszloattilatoth.jssh.proxy.Name;
import me.laszloattilatoth.jssh.proxy.NameWithId;

import java.util.HashMap;
import java.util.Map;

public class Macs {
    private static final Map<Integer, Mac> macs = new HashMap<>();

    public static Mac getById(int nameId) {
        return macs.get(nameId);
    }

    public static Mac getByName(String name) {
        for (Mac m : macs.values()) {
            if (m.name().equals(name)) {
                return m;
            }
        }

        return null;
    }

    public static Mac getByNameWithId(NameWithId nameWithId) {
        return getById(nameWithId.getNameId());
    }

    static {
        put("hmac-sha1");
    }

    private static void put(String name) {
        int nameId = Name.getNameId(name);
        macs.put(nameId, new Mac(name, nameId));
    }
}
