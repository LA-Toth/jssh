package me.laszloattilatoth.jssh.proxy;

import java.io.IOException;
import java.io.InputStream;

/**
 * Encapsulates a low level buffer, as of now to read a line terminated by NEW LINE character.
 * <p>
 * The members are public for simplicity
 */
public class Buffer {
    public byte[] buffer;
    public int lastBytePosition;

    public Buffer() {
        this(Constant.MINIMUM_MAX_PACKET_SIZE);
    }

    public Buffer(int size) {
        buffer = new byte[size];
    }

    /**
     * Reads a line from @inputStream terminated by NL (0x0a).
     * <p>
     * Updates the size member and sets it to the size of the read data including the terminating
     * new line character.
     *
     * @param inputStream
     * @return The length of the line without the LF or CR LF bytes.
     * @throws IOException
     */
    public int readLine(InputStream inputStream) throws IOException {
        int readByte = 0;
        lastBytePosition = 0;
        while (lastBytePosition < buffer.length) {
            readByte = inputStream.read();
            if (readByte < 0) break;
            buffer[lastBytePosition] = (byte) readByte;
            lastBytePosition++;

            // Not verifying if the data is CR LF or just LF here
            if (readByte == '\n') break;
        }

        if (readByte < 0) {
            throw new IOException("Connection reset by peers");
        }

        int readByteCount = lastBytePosition;
        if (buffer[readByteCount - 1] == '\n') {
            readByteCount--;
            if (readByteCount > 0 && buffer[readByteCount - 1] == '\r')
                readByteCount--;
        }

        return readByteCount;
    }
}
