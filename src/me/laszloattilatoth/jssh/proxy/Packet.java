package me.laszloattilatoth.jssh.proxy;

import me.laszloattilatoth.jssh.Util;

import java.util.logging.Logger;

/**
 * Represents an SSH packet
 */
public class Packet {
    private byte[] buffer;

    public Packet(byte[] bytes) {
        this.buffer = bytes;
    }

    public byte getType() {
        return buffer[0];
    }

    public void dump() {
        Logger logger = Util.sshLogger();
        logger.info(() -> String.format("Packet dump follows; packet_type='%d', packet_type_hex='%x', length='%d'",
                getType(), getType(), buffer.length));
        Util.logBytes(logger, buffer);
    }
}
