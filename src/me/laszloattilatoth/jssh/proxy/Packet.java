package me.laszloattilatoth.jssh.proxy;

import me.laszloattilatoth.jssh.Util;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Represents an SSH packet
 */
public class Packet {
    private byte[] buffer;
    private int position = 0;

    public Packet(byte[] bytes) {
        this.buffer = bytes;
    }

    private void checkPosition(int requiredLength) throws BufferEndReachedException {
        if (position + requiredLength > buffer.length) {
            Util.sshLogger().severe(String.format("Unable to read required bytes from packet; required='%d'", requiredLength));
            throw new BufferEndReachedException("Unable to read required bytes from packet");
        }
    }

    public byte getType() {
        return buffer[0];
    }

    public int getLength() {
        return buffer.length;
    }

    public void dump() {
        Logger logger = Util.sshLogger();
        logger.info(() -> String.format("Packet dump follows; packet_type='%d', packet_type_hex='%x', length='%d'",
                getType(), getType(), buffer.length));
        Util.logBytes(logger, buffer);
    }

    public int getPosition() {
        return position;
    }

    public void resetPosition() {
        position = 0;
    }

    public int readByte() throws BufferEndReachedException {
        checkPosition(1);
        return buffer[position++] & 0xff;
    }

    private int readByteUnchecked() {
        return buffer[position++] & 0xff;
    }

    public byte[] readBytes(int length) throws BufferEndReachedException {
        checkPosition(length);
        byte[] result = new byte[length];
        System.arraycopy(buffer, position, result, 0, length);
        position += length;
        return result;
    }

    /* readX: based on RFC 2451 5.  Data Type Representations Used in the SSH Protocols */

    public boolean readBoolean() throws BufferEndReachedException {
        return readByte() != 0;
    }

    public int readUint32() throws BufferEndReachedException {
        checkPosition(4);
        logBytes(4);
        return ((readByteUnchecked() << 24) + (readByteUnchecked() << 16) + (readByteUnchecked() << 8) + readByteUnchecked());
    }

    private void logBytes(int length) {
        Logger logger = Util.sshLogger();
        if (!logger.isLoggable(Level.FINEST))
            return;

        logger.finest(String.format("Log packet bytes; position='%d', hexpos='%04x', count='%d'", position, position, length));
        for (int i = 0; i != length; ++i) {
            int val = buffer[position + i] & 0xff;
            logger.finest(String.format("Packet byte; hex='%02x', dec='%d', val='%c', offset='%d'",
                    val, val,
                    (val < 32 || val > 126) ? '.' : val,
                    i));
        }
    }

    public long readUint32AsLong() throws BufferEndReachedException {
        checkPosition(4);
        logBytes(4);
        return (((long) readByteUnchecked() << 24) + ((long) readByteUnchecked() << 16) + ((long) readByteUnchecked() << 8) + ((long) readByteUnchecked()));
    }

    public long readUint64() throws BufferEndReachedException {
        checkPosition(8);
        logBytes(8);
        return (((long) readByteUnchecked() << 56) + ((long) readByteUnchecked() << 48) +
                ((long) readByteUnchecked() << 40) + ((long) readByteUnchecked() << 32) +
                ((long) readByteUnchecked() << 24) + ((long) readByteUnchecked() << 16) +
                ((long) readByteUnchecked() << 8) + ((long) readByteUnchecked()));
    }

    public String readString() throws BufferEndReachedException {
        int length = readUint32();
        checkPosition(length);

        String s = new String(buffer, position, length);
        position += length;
        return s;
    }

    public byte[] readMpInt() throws BufferEndReachedException {
        int length = readUint32();
        checkPosition(length);

        byte[] b = Arrays.copyOfRange(buffer, position, length);
        position += length;
        return b;
    }

    public ArrayList<String> readNameList() throws BufferEndReachedException {
        int length = readUint32();
        checkPosition(length);

        ArrayList<String> result = Util.splitNameList(buffer, position, length);
        position += length;

        return result;
    }

    public int[] readNameIdList() throws BufferEndReachedException {
        return Util.getIdListFromNameArrayList(readNameList());
    }

    public static final class BufferEndReachedException extends Exception {
        BufferEndReachedException(String s) {
            super(s);
        }
    }
}
