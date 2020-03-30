package me.laszloattilatoth.jssh.proxy;

import me.laszloattilatoth.jssh.Config;
import me.laszloattilatoth.jssh.Util;

import java.io.*;
import java.lang.ref.WeakReference;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Based on RFC 4253 - The Secure Shell (SSH) Transport Layer Protocol
 */
public class TransportLayer {
    /**
     * RFC 4253 6.1 Maximum packet length
     * /* The implementation MUST be able to process packets with size 35000
     */
    public static final int MINIMUM_MAX_PACKET_SIZE = 35000;

    public static final byte[] SSH_VERSION_STRING_PREFIX = "SSH-".getBytes();

    private final WeakReference<SshProxy> proxy;
    private final Config config;
    private final Logger logger;
    protected DataInputStream dataInputStream = null;
    protected DataOutputStream dataOutputStream = null;
    private int macLength = 0;

    public TransportLayer(SshProxy proxy, InputStream is, OutputStream os) {
        this.proxy = new WeakReference<>(proxy);
        this.logger = proxy.getLogger();
        this.config = proxy.getConfig();
        this.dataInputStream = new DataInputStream(is);
        this.dataOutputStream = new DataOutputStream(os);
    }

    /**
     * Starts the layer, aka. send / receive SSH-2.0... string
     */
    public void start() throws TransportLayerException {
        writeVersionString();
        readVersionString();

        try {
            Packet packet = readPacket();
            packet.dump();
        } catch (IOException e) {
            logger.severe("Unable to read version string;");
            Util.logException(logger, e, Level.INFO);
            throw new TransportLayerException("Unable to read packet");
        }
    }

    private void writeVersionString() {
        logger.info("Sending version string; version='SSH-2.0-JSSH'");
        try {
            this.dataOutputStream.writeBytes("SSH-2.0-JSSH\r\n");
        } catch (IOException e) {
            logger.severe("Unable to send version string;");
            Util.logException(logger, e, Level.INFO);
        }
    }

    private void readVersionString() throws TransportLayerException {
        try {
            Buffer buffer = new Buffer();

            int readBytes = readVersionStringToBuffer(buffer);
            String versionString = new String(buffer.buffer, 0, readBytes);

            if (!versionString.startsWith("SSH-2.0")) {
                logger.severe(String.format("Unsupported SSH protocol; verson_string='%s'", versionString));
                throw new TransportLayerException("Unsupported SSH protocol");
            }

            logger.info("Remote ID String: " + versionString);
        } catch (
                IOException e) {
            Util.logExceptionWithBacktrace(logger, e, Level.SEVERE);
        }
    }

    private int readVersionStringToBuffer(Buffer buffer) throws IOException, TransportLayerException {
        int readBytes;
        while (true) {
            readBytes = buffer.readLine(dataInputStream);

            if (readBytes < SSH_VERSION_STRING_PREFIX.length + 3) continue;

            boolean match = true;
            for (int idx = 0; idx < SSH_VERSION_STRING_PREFIX.length; ++idx) {
                if (buffer.buffer[idx] != SSH_VERSION_STRING_PREFIX[idx]) {
                    match = false;
                    break;
                }
            }
            if (!match)
                continue;

            break;
        }

        return readBytes;
    }

    /**
     * Read packet as RFC 4253, 6.  Binary Packet Protocol
     */
    private Packet readPacket() throws IOException {
        logger.info("Reading next packet");
        int packetLength = dataInputStream.readInt();
        byte paddingLength = dataInputStream.readByte();
        logger.info(() -> String.format("Read packet header; length='%d', padding_length='%d'",
                packetLength, paddingLength));

        byte[] data = dataInputStream.readNBytes(packetLength - paddingLength - 1);
        logger.fine(() -> "Read packet data;");
        if (paddingLength > 0)
            dataInputStream.readNBytes(paddingLength);
        logger.fine(() -> "Read packet padding;");

        if (macLength > 0)
            dataInputStream.readNBytes(macLength);

        return new Packet(data);
    }
}
