package me.laszloattilatoth.jssh.kex;

import me.laszloattilatoth.jssh.proxy.Constant;
import me.laszloattilatoth.jssh.proxy.Packet;

public class KexInitPacket {
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

    private static final int ENTRY_NON_EMPTY_MAX = ENTRY_COMP_ALGOS_S2C + 1;

    public static final int COOKIE_LEN = 16;

    private final String[] entries = new String[ENTRY_MAX];
    public boolean follows = false;

    public void setAlgos(int index, String algos) throws KexException {
        if (index < 0 || index > ENTRY_MAX)
            throw new KexException("Algorithm index is out of range");

        entries[index] = algos;
    }

    public String getAlgos(int index) throws KexException {
        if (index < 0 || index > ENTRY_MAX)
            throw new KexException("Algorithm index is out of range");

        return entries[index];
    }

    public void addToPacket(Packet packet) throws Packet.BufferEndReachedException {
        packet.resetPosition();

        for (int i = 0; i != COOKIE_LEN; ++i) {
            packet.writeByte(0);
        }

        for (int i = 0; i != ENTRY_MAX; ++i) {
            packet.writeString(entries[i]);
        }

        packet.writeBoolean(false); // No packet follows
        packet.writeUint32(0);      // reserved
    }

    public void readFromPacket(Packet packet) throws Packet.BufferEndReachedException {
        packet.readByte();   // type
        packet.readBytes(COOKIE_LEN);
        readEntriesFromPacket(packet);
        follows = packet.readBoolean();
        packet.readUint32();  // reserved
    }

    private void readEntriesFromPacket(Packet packet) throws Packet.BufferEndReachedException {
        for (int i = 0; i != ENTRY_MAX; ++i) {
            entries[i] = packet.readString();
        }
    }

    public boolean valid() {
        for (int i = 0; i != ENTRY_NON_EMPTY_MAX; ++i) {
            if (entries[i] == null || entries[i].length() == 0)
                return false;
        }

        return true;
    }

    public void writeToPacket(Packet packet) throws Packet.BufferEndReachedException {
        packet.writeByte(Constant.SSH_MSG_KEXINIT);
        for (int i = 0; i != COOKIE_LEN; ++i)
            packet.writeByte(0);  // FIXME: Security????
        for (int i = 0; i != ENTRY_MAX; ++i) {
            packet.writeString(entries[i]);
        }
        packet.writeBoolean(false);
        packet.writeUint32(0);   // reserved
    }
}
