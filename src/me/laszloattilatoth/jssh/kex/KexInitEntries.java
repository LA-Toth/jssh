package me.laszloattilatoth.jssh.kex;

import me.laszloattilatoth.jssh.proxy.NameListWithIds;

public class KexInitEntries {
    public static final int ENTRY_KEX_ALGOS = 0;
    public static final int ENTRY_SERVER_HOST_KEY_ALG = 1;
    public static final int ENTRY_ENC_ALGOS_C2S = 2;
    public static final int ENTRY_ENC_ALGOS_S2C = 3;
    public static final int ENTRY_MAC_ALGOS_C2S = 4;
    public static final int ENTRY_MAC_ALGOS_S2C = 5;
    public static final int ENTRY_COMP_ALGOS_C2S = 6;
    public static final int ENTRY_COMP_ALGOS_S2C = 7;
    public static final int ENTRY_LANG_C2S = 8;
    public static final int ENTRY_LANG_S2C = 9;
    public static final int ENTRY_MAX = ENTRY_LANG_S2C + 1;

    public static final int ENTRY_NON_EMPTY_MAX = ENTRY_COMP_ALGOS_S2C + 1;

    public final NameListWithIds[] entries = new NameListWithIds[ENTRY_MAX];
}
