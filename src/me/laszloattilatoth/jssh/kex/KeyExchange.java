package me.laszloattilatoth.jssh.kex;

import me.laszloattilatoth.jssh.Config;
import me.laszloattilatoth.jssh.Util;
import me.laszloattilatoth.jssh.proxy.NameListWithIds;
import me.laszloattilatoth.jssh.proxy.Packet;
import me.laszloattilatoth.jssh.proxy.Side;
import me.laszloattilatoth.jssh.transportlayer.TransportLayer;
import me.laszloattilatoth.jssh.transportlayer.TransportLayerException;

import java.lang.ref.WeakReference;
import java.util.logging.Logger;

public class KeyExchange {
    private final WeakReference<TransportLayer> transportLayer;
    private final Side side;
    private Config config;
    private Logger logger;
    private NameListWithIds kexAlgorithms;
    private NameListWithIds encryptionAlgorithms;
    private NameListWithIds macAlgorithms;
    private NameListWithIds compressionAlgorithms;
    private NameListWithIds peerKexAlgorithms;
    private NameListWithIds peerC2SEncryptionAlgorithms;
    private NameListWithIds peerS2CEncryptionAlgorithms;
    private NameListWithIds peerC2SMacAlgorithms;
    private NameListWithIds peerS2CMacAlgorithms;
    private NameListWithIds peerC2SCompressionAlgorithms;
    private NameListWithIds peerS2CCompressionAlgorithms;
    private State state = State.DEFAULT;

    public KeyExchange(TransportLayer transportLayer) {
        this.transportLayer = new WeakReference<>(transportLayer);
        this.config = transportLayer.getConfig();
        this.side = transportLayer.side;
        this.logger = transportLayer.getLogger();

        this.kexAlgorithms = NameListWithIds.create(Util.getConfigValueBySide(this.config, this.side, "kex_algorithms"));
        this.encryptionAlgorithms = NameListWithIds.create(Util.getConfigValueBySide(this.config, this.side, "encryption_algorithms"));
        this.macAlgorithms = NameListWithIds.create(Util.getConfigValueBySide(this.config, this.side, "mac_algorithms"));
        this.compressionAlgorithms = NameListWithIds.create(Util.getConfigValueBySide(this.config, this.side, "compression_algorithms"));
    }

    /// RFC 4253 7.1.  Algorithm Negotiation (SSH_MSG_KEXINIT)
    public void processMsgKexInit(Packet packet) throws TransportLayerException {
        boolean follows;
        byte[] cookie;

        try {
            packet.readByte();
            cookie = packet.readBytes(16);
            peerKexAlgorithms = NameListWithIds.createAndLog(packet.readString(), logger, "KEX algos");
            peerC2SEncryptionAlgorithms = NameListWithIds.createAndLog(packet.readString(), logger, "C2S Encryption algos");
            peerS2CEncryptionAlgorithms = NameListWithIds.createAndLog(packet.readString(), logger, "S2C Encryption algos");
            peerC2SMacAlgorithms = NameListWithIds.createAndLog(packet.readString(), logger, "C2S Mac algos");
            peerS2CMacAlgorithms = NameListWithIds.createAndLog(packet.readString(), logger, "S2C Mac algos");
            peerC2SCompressionAlgorithms = NameListWithIds.createAndLog(packet.readString(), logger, "C2S Compression algos");
            peerS2CCompressionAlgorithms = NameListWithIds.createAndLog(packet.readString(), logger, "S2C Compression algos");
            packet.readString();
            packet.readString();
            follows = packet.readBoolean();
        } catch (Packet.BufferEndReachedException e) {
            logger.severe(() -> String.format("Unable to parse SSH_MSG_KEXINIT; error='%s'", e.getMessage()));
            throw new KexException(e.getMessage());
        }
    }

    private enum State {
        DEFAULT,
        AFTER_KEX,
        KEX,
    }
}
