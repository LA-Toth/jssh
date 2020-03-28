package me.laszloattilatoth.jssh.proxy;

import me.laszloattilatoth.jssh.Config;
import me.laszloattilatoth.jssh.Util;

import java.io.*;
import java.lang.ref.WeakReference;
import java.nio.charset.StandardCharsets;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Based on RFC 4253 - The Secure Shell (SSH) Transport Layer Protocol
 */
public class TransportLayer {
    private final WeakReference<SshProxy> proxy;
    private final Config config;
    private final Logger logger;
    protected BufferedInputStream inputStream;
    protected BufferedOutputStream outputStream;
    private DataInputStream dataInputStream = null;
    private DataOutputStream dataOutputStream = null;
    private int macLength = 0;

    public TransportLayer(SshProxy proxy, InputStream is, OutputStream os) {
        this.proxy = new WeakReference<>(proxy);
        this.logger = proxy.getLogger();
        this.config = proxy.getConfig();
        this.inputStream = new BufferedInputStream(is);
        this.outputStream = new BufferedOutputStream(os);
    }

    /**
     * Starts the layer, aka. send / receive SSH-2.0... string
     */
    public void start() throws TransportLayerException {
        writeVersionString();
        readVersionString();

        this.dataInputStream = new DataInputStream(this.inputStream);
        this.dataOutputStream = new DataOutputStream(this.outputStream);

        try {
            byte[] packet = readPacket();
            Util.logBytes(packet);
        } catch (IOException e) {
            logger.severe("Unable to read version string;");
            Util.logException(logger, e, Level.INFO);
            throw new TransportLayerException("Unable to read packet");
        }
    }

    private void writeVersionString() {
        try {
            Writer out = new OutputStreamWriter(outputStream);
            out.write("SSH-2.0-JSSH\r\n");
            out.flush();
            this.outputStream.flush();
        } catch (IOException e) {
            logger.severe("Unable to send version string;");
            Util.logException(logger, e, Level.INFO);
        }
    }

    private void readVersionString() throws TransportLayerException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8));

        try {
            String versionString = reader.readLine();
            while (!versionString.startsWith("SSH-"))
                versionString = reader.readLine();

            logger.info("Remote ID String: " + versionString);

            if (!versionString.startsWith("SSH-2.0")) {
                logger.severe(String.format("Unsupported SSH protocol; verson_string='%s'", versionString));
                throw new TransportLayerException("Unsupported SSH protocol");
            }
        } catch (IOException e) {
            Util.logExceptionWithBacktrace(logger, e, Level.SEVERE);
        }
    }

    /**
     * Read packet as RFC 4253, 6.  Binary Packet Protocol
     */
    private byte[] readPacket() throws IOException {
        int packetLength = dataInputStream.readInt();
        byte paddingLength = dataInputStream.readByte();
        logger.info(() -> String.format("Read packet header; length='%d', padding_length='%d'",
                packetLength, paddingLength));

        byte[] result = dataInputStream.readNBytes(packetLength - paddingLength - 1);
        logger.fine(() -> "Read packet data;");
        if (paddingLength > 0)
            dataInputStream.readNBytes(paddingLength);
        logger.fine(() -> "Read packet padding;");

        if (macLength > 0)
            dataInputStream.readNBytes(macLength);

        return result;
    }
}
