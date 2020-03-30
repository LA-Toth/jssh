package me.laszloattilatoth.jssh.proxy;

import me.laszloattilatoth.jssh.Util;

import java.util.ArrayList;
import java.util.Arrays;
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
        if (position + requiredLength < buffer.length) {
            Util.sshLogger().severe(String.format("Unable to read required bytes from packet; required='%d'", requiredLength));
            throw new BufferEndReachedException("Unable to read required bytes from packet");
        }
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

    public int getPosition() {
        return position;
    }

    public byte readByte() throws BufferEndReachedException {
        checkPosition(1);
        return buffer[position++];
    }

    /* readX: based on RFC 2451 5.  Data Type Representations Used in the SSH Protocols */

    public boolean readBoolean() throws BufferEndReachedException {
        return readByte() != 0;
    }

    public int readUint32() throws BufferEndReachedException {
        checkPosition(4);
        return ((buffer[position++] << 24) + (buffer[position++] << 16) + (buffer[position++] << 8) + (buffer[position++]));
    }

    public long readUint32AsLong() throws BufferEndReachedException {
        checkPosition(4);
        return (((long) buffer[position++] << 24) + (buffer[position++] << 16) + (buffer[position++] << 8) + (buffer[position++]));
    }

    public long readUint64() throws BufferEndReachedException {
        checkPosition(4);
        return (((long) buffer[position++] << 56) + ((long) buffer[position++] << 48) +
                ((long) buffer[position++] << 40) + ((long) buffer[position++] << 32) +
                (buffer[position++] << 24) + (buffer[position++] << 16) +
                (buffer[position++] << 8) + (buffer[position++]));
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

        int startPos = position;
        int endPos = position;
        ArrayList<String> result = new ArrayList<>();

        for (int i = 0; i < length; ++i) {
            if (buffer[endPos] == ',') {
                result.add(new String(buffer, startPos, endPos - startPos - 1));
                startPos = endPos + 1;
            }
            endPos++;
        }

        result.add(new String(buffer, startPos, endPos - startPos - 1));
        position += length;

        return result;
    }

    public static final class BufferEndReachedException extends Exception {
        BufferEndReachedException(String s) {
            super(s);
        }
    }
}
