package me.laszloattilatoth.jssh.kex;

import me.laszloattilatoth.jssh.proxy.Constant;
import me.laszloattilatoth.jssh.proxy.NameListWithIds;
import me.laszloattilatoth.jssh.proxy.Packet;

public class KexInitPacket extends KexInitEntries {
    public static final int COOKIE_LEN = 16;

    public boolean follows = false;

    public void readFromPacket(Packet packet) throws Packet.BufferEndReachedException {
        packet.readByte();   // type
        packet.readBytes(COOKIE_LEN);
        readEntriesFromPacket(packet);
        follows = packet.readBoolean();
        packet.readUint32();  // reserved
    }

    private void readEntriesFromPacket(Packet packet) throws Packet.BufferEndReachedException {
        for (int i = 0; i != ENTRY_MAX; ++i) {
            entries[i] = NameListWithIds.create(packet.readString());
        }
    }

    public boolean valid() {
        for (int i = 0; i != ENTRY_NON_EMPTY_MAX; ++i) {
            if (entries[i] == null || entries[i].size() == 0)
                return false;
        }

        return true;
    }

    public void writeToPacket(Packet packet) throws Packet.BufferEndReachedException {
        packet.writeByte(Constant.SSH_MSG_KEXINIT);
        for (int i = 0; i != COOKIE_LEN; ++i)
            packet.writeByte(0);  // FIXME: Security????
        for (int i = 0; i != ENTRY_MAX; ++i) {
            packet.writeString(entries[i].getNameList());
        }
        packet.writeBoolean(false);
        packet.writeUint32(0);   // reserved
    }
}
