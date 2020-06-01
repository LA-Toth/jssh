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
    public static final int MAX_SIZE = 0x8000000; // as in OpenSSH buffer
    public static final int INIT_SIZE = 256;
    public static final int SIZE_INC = 256;

    private byte[] buffer;
    private int position = 0;
    private int maxSize;
    private int bufferEnd;
    private int size;   // size of valid data (buffer may be larger)

    public Packet(byte[] bytes) {
        this.buffer = bytes;
        this.maxSize = this.buffer.length;
        this.size = this.buffer.length;
        this.bufferEnd = this.buffer.length;
    }

    public Packet() {
        this.buffer = new byte[INIT_SIZE];
        this.maxSize = MAX_SIZE;
        this.size = 0;
        this.bufferEnd = 0;
    }

    private void checkPosition(int requiredLength) throws BufferEndReachedException {
        if (position + requiredLength > buffer.length) {
            Util.sshLogger().severe(String.format("Unable to read required bytes from packet; required='%d'", requiredLength));
            throw new BufferEndReachedException("Unable to read required bytes from packet");
        }
    }

    private void preserve(int requiredLength) throws BufferEndReachedException {
        if (requiredLength > maxSize || maxSize - requiredLength < size - position) {
            Util.sshLogger().severe(String.format("Unable to allocate required bytes into packet; required='%d'", requiredLength));
            throw new BufferEndReachedException("Unable to allocate bytes in packet");
        }

        if (size + requiredLength < buffer.length)
            return;

        int newSize = ((size + requiredLength + SIZE_INC - 1) / SIZE_INC) * SIZE_INC;
        byte[] newBuffer = new byte[newSize];

        System.arraycopy(buffer, 0, newBuffer, 0, buffer.length);
        buffer = newBuffer;
    }

    public byte getType() {
        return buffer[0];
    }

    public int getAllocatedSize() {
        return buffer.length;
    }

    public int getSize() {
        return size;
    }

    public int getBufferEnd() {
        return bufferEnd;
    }

    public byte[] getBufferCopy() {
        byte[] copy = new byte[size];
        System.arraycopy(buffer, 0, copy, 0, size);
        return copy;
    }

    public void dump() {
        Logger logger = Util.sshLogger();
        logger.info(() -> String.format("Packet dump follows; packet_type='%d', packet_type_hex='%x', length='%d'",
                getType(), getType(), size));
        Util.logBytes(logger, buffer, bufferEnd);
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

    public void resetType(byte packetType) {
        resetPosition();
        buffer[0] = packetType;
    }

    private void writeByteUnchecked(byte b) {
        buffer[position++] = b;
        size++;
        bufferEnd = position;
    }

    public void writeByte(int b) throws BufferEndReachedException {
        preserve(1);
        writeByteUnchecked((byte) b);
    }

    public void writeBoolean(boolean b) throws BufferEndReachedException {
        writeByte(b ? 1 : 0);
    }

    public void writeBytes(byte[] b) throws BufferEndReachedException {
        preserve(b.length);
        System.arraycopy(b, 0, buffer, position, b.length);
        position += b.length;
        size += b.length;
        bufferEnd = position;
    }

    public void writeUint32(long l) throws BufferEndReachedException {
        preserve(4);
        writeByteUnchecked((byte) (l >> 24));
        writeByteUnchecked((byte) (l >> 16));
        writeByteUnchecked((byte) (l >> 8));
        writeByteUnchecked((byte) l);
    }

    public void writeUint64(long l) throws BufferEndReachedException {
        preserve(8);
        writeByteUnchecked((byte) (l >> 56));
        writeByteUnchecked((byte) (l >> 48));
        writeByteUnchecked((byte) (l >> 40));
        writeByteUnchecked((byte) (l >> 32));
        writeByteUnchecked((byte) (l >> 24));
        writeByteUnchecked((byte) (l >> 16));
        writeByteUnchecked((byte) (l >> 8));
        writeByteUnchecked((byte) l);
    }

    public void writeString(String s) throws BufferEndReachedException {
        byte[] bytes = s.getBytes();
        preserve(4 + bytes.length);
        writeUint32(bytes.length);
        writeBytes(bytes);
    }

    public static final class BufferEndReachedException extends Exception {
        BufferEndReachedException(String s) {
            super(s);
        }
    }
}
