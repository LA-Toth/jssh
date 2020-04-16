package me.laszloattilatoth.jssh.transportlayer;

import me.laszloattilatoth.jssh.Config;
import me.laszloattilatoth.jssh.Util;
import me.laszloattilatoth.jssh.kex.KeyExchange;
import me.laszloattilatoth.jssh.proxy.*;

import java.io.*;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Based on RFC 4253 - The Secure Shell (SSH) Transport Layer Protocol
 */
public abstract class TransportLayer {
    private static final String UNKNOWN_STR = "(unknown)";
    private static final String NOT_IMPLEMENTED_STR = "(not implemented)";
    public final Side side;
    private final WeakReference<SshProxy> proxy;
    private final Config config;
    private final Logger logger;
    private final KeyExchange kex;
    protected DataInputStream dataInputStream = null;
    protected DataOutputStream dataOutputStream = null;
    private int macLength = 0;
    private PacketHandler[] packetHandlers = new PacketHandler[256];
    private String[] packetTypeNames = new String[256];

    private List<Packet> replayPackets = new ArrayList<>();

    public TransportLayer(SshProxy proxy, InputStream is, OutputStream os, Side side) {
        this.proxy = new WeakReference<>(proxy);
        this.logger = proxy.getLogger();
        this.config = proxy.getConfig();
        this.dataInputStream = new DataInputStream(is);
        this.dataOutputStream = new DataOutputStream(os);
        this.side = side;
        this.kex = new KeyExchange(this);
        this.setupHandlers();
    }

    private void setupHandlers() {
        for (int i = 0; i != packetHandlers.length; ++i)
            registerHandler(i, this::handleNotImplementedPacket, NOT_IMPLEMENTED_STR);

        registerHandler(Constant.SSH_MSG_DISCONNECT, this::processMsgDisconnect, Constant.SSH_MSG_NAMES[Constant.SSH_MSG_DISCONNECT]);
        registerHandler(Constant.SSH_MSG_IGNORE, this::processMsgIgnore, Constant.SSH_MSG_NAMES[Constant.SSH_MSG_IGNORE]);
        registerHandler(Constant.SSH_MSG_UNIMPLEMENTED, this::processMsgUnimplemented, Constant.SSH_MSG_NAMES[Constant.SSH_MSG_UNIMPLEMENTED]);
        registerHandler(Constant.SSH_MSG_DEBUG, this::processMsgIgnore, Constant.SSH_MSG_NAMES[Constant.SSH_MSG_DEBUG]);
        registerHandler(Constant.SSH_MSG_KEXINIT, kex::processMsgKexInit, Constant.SSH_MSG_NAMES[Constant.SSH_MSG_KEXINIT]);
    }

    public void registerHandler(int packetType, PacketHandler handler, String packetTypeName) {
        packetHandlers[packetType] = handler;
        packetTypeNames[packetType] = packetTypeName;
    }

    public void unregisterHandler(int packetType) {
        registerHandler(packetType, this::handleNotImplementedPacket, NOT_IMPLEMENTED_STR);
    }

    public final Config getConfig() {
        return config;
    }

    public final Logger getLogger() {
        return logger;
    }

    /**
     * Starts the layer, aka. send / receive SSH-2.0... string
     * and do the first KEX
     */
    public void start() throws TransportLayerException {
        writeVersionString();
        readVersionString();
        exchangeKeys();
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

            if (readBytes < Constant.SSH_VERSION_STRING_PREFIX.length + 3) continue;

            boolean match = true;
            for (int idx = 0; idx < Constant.SSH_VERSION_STRING_PREFIX.length; ++idx) {
                if (buffer.buffer[idx] != Constant.SSH_VERSION_STRING_PREFIX[idx]) {
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

    private void exchangeKeys() throws TransportLayerException {
        try {
            readAndHandlePacket();
        } catch (IOException e) {
            logger.severe("Unable to read version string;");
            Util.logException(logger, e, Level.INFO);
            throw new TransportLayerException("Unable to read packet");
        }
    }

    public void readAndHandlePacket() throws IOException, TransportLayerException {
        Packet packet = readPacket();
        packet.dump();
        byte packetType = packet.getType();
        logger.info(() -> String.format("Processing packet; type='%d', hex_type='%x', type_name='%s', length='%d'",
                packetType, packetType, packetTypeNames[packetType], packet.getLength()));

        if (kex.getState() == KeyExchange.State.WAIT_FOR_OTHER_KEXINIT && packetType != Constant.SSH_MSG_KEXINIT)
            storePacket(packet);
        else
            packetHandlers[packetType].handle(packet);
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

    private void processMsgDisconnect(Packet packet) throws TransportLayerException {
        try {
            packet.readByte();
            long reasonCode = packet.readUint32AsLong();
            String description = packet.readString();
            String reason = reasonCode <= Constant.SSH_DISCONNECT_MAX_REASON_CODE ? Constant.SSH_DISCONNECT_NAMES[(int) reasonCode] : "(Unknown)";
            logger.info(String.format("Received disconnect message; reason_code='%s', reason='%s', description='%s'", reasonCode, reason, description));
            Objects.requireNonNull(proxy.get()).shouldQuit();
        } catch (Packet.BufferEndReachedException e) {
            throw new TransportLayerException(e.getMessage());
        }
    }

    private void processMsgIgnore(Packet packet) {
    }

    private void processMsgUnimplemented(Packet packet) {
        byte packetType = packet.getType();
        logger.info(() -> String.format("Processing unimplemented packet; type='%d', hex_type='%x'",
                packetType, packetType));
    }

    private void handleNotImplementedPacket(Packet packet) {
        // TODO: what to do if a packet is not handled
    }

    private void storePacket(Packet packet) {
        logger.info(() -> "Waiting for SSH_MSG_KEXINIT from other side, storing packet;");
        replayPackets.add(packet);
    }
}
