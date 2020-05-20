package me.laszloattilatoth.jssh.kex;

import me.laszloattilatoth.jssh.Config;
import me.laszloattilatoth.jssh.Util;
import me.laszloattilatoth.jssh.proxy.*;
import me.laszloattilatoth.jssh.transportlayer.TransportLayer;
import me.laszloattilatoth.jssh.transportlayer.TransportLayerException;

import java.lang.ref.WeakReference;
import java.util.logging.Logger;

public class KeyExchange {
    private final WeakReference<TransportLayer> transportLayer;
    private final Side side;
    private final Config config;
    private final Logger logger;
    private final NameListWithIds kexAlgorithms;
    private final NameListWithIds hostKeyAlgorithms;
    private final NameListWithIds encryptionAlgorithms;
    private final NameListWithIds macAlgorithms;
    private final NameListWithIds compressionAlgorithms;
    private State state = State.INITIAL;
    private NegotiatedAlgorithms negotiatedAlgorithms;

    public KeyExchange(TransportLayer transportLayer) {
        this.transportLayer = new WeakReference<>(transportLayer);
        this.config = transportLayer.getConfig();
        this.side = transportLayer.side;
        this.logger = transportLayer.getLogger();

        this.kexAlgorithms = NameListWithIds.create(Util.getConfigValueBySide(this.config, this.side, "kex_algorithms"));
        this.hostKeyAlgorithms = NameListWithIds.create(Util.getConfigValueBySide(this.config, this.side, "hostkey_algorithms"));
        this.encryptionAlgorithms = NameListWithIds.create(Util.getConfigValueBySide(this.config, this.side, "encryption_algorithms"));
        this.macAlgorithms = NameListWithIds.create(Util.getConfigValueBySide(this.config, this.side, "mac_algorithms"));
        this.compressionAlgorithms = NameListWithIds.create(Util.getConfigValueBySide(this.config, this.side, "compression_algorithms"));

        /*
        this.kexAlgorithms.filter();
        this.encryptionAlgorithms.filter([Name.SSH_NAME_NONE]);
        this.macAlgorithms.filter([Name.SSH_NAME_NONE]);
        this.compressionAlgorithms.filter([Name.SSH_NAME_NONE]);
         */
    }

    public State getState() {
        return state;
    }

    public void sendInitialMsgKexInit() throws KexException {
        KexInitPacket initPacket = new KexInitPacket();
        initPacket.setAlgos(KexInitPacket.ENTRY_KEX_ALGOS, kexAlgorithms.getNameList());
        initPacket.setAlgos(KexInitPacket.ENTRY_SERVER_HOST_KEY_ALG, hostKeyAlgorithms.getNameList());
        initPacket.setAlgos(KexInitPacket.ENTRY_ENC_ALGOS_C2S, encryptionAlgorithms.getNameList());
        initPacket.setAlgos(KexInitPacket.ENTRY_ENC_ALGOS_S2C, encryptionAlgorithms.getNameList());
        initPacket.setAlgos(KexInitPacket.ENTRY_MAC_ALGOS_C2S, macAlgorithms.getNameList());
        initPacket.setAlgos(KexInitPacket.ENTRY_MAC_ALGOS_S2C, macAlgorithms.getNameList());
        initPacket.setAlgos(KexInitPacket.ENTRY_COMP_ALGOS_C2S, compressionAlgorithms.getNameList());
        initPacket.setAlgos(KexInitPacket.ENTRY_COMP_ALGOS_S2C, compressionAlgorithms.getNameList());
        initPacket.setAlgos(KexInitPacket.ENTRY_LANG_C2S, "");
        initPacket.setAlgos(KexInitPacket.ENTRY_LANG_S2C, "");

        Packet packet = new Packet();
        try {
            initPacket.writeToPacket(packet);
        } catch (Packet.BufferEndReachedException e) {
            logger.severe(() -> String.format("Unable to send SSH_MSG_KEXINIT; error='%s'", e.getMessage()));
            throw new KexException(e.getMessage());
        }
    }

    /// RFC 4253 7.1.  Algorithm Negotiation (SSH_MSG_KEXINIT)
    public void processMsgKexInit(Packet packet) throws TransportLayerException {
        KexInitPacket initPacket = new KexInitPacket();
        try {
            initPacket.readFromPacket(packet);
        } catch (Packet.BufferEndReachedException e) {
            logger.severe(() -> String.format("Unable to parse SSH_MSG_KEXINIT; error='%s'", e.getMessage()));
            throw new KexException(e.getMessage());
        }

        if (!initPacket.valid()) {
            logger.severe("Peer KEXINIT packet contains at least algorithm list which is empty or contains only unknown algos;");
            throw new KexException("Unable to process SSH_MSG_KEXINIT, no known algorithms;");
        }

        negotiatedAlgorithms = guess();
        logger.fine("The negotiated algos is " + (negotiatedAlgorithms != null ? "NOT " : "") + "NULL");

        if (negotiatedAlgorithms == null) {
            if (initPacket.follows)
                state = State.DROP_GUESSED_PACKET;
            negotiatedAlgorithms = calculateAlgorithms();
        }

        if (negotiatedAlgorithms == null) {
            throw new KexException("No matching algo");
        }
    }

    /**
     * Guesses the algorithms for the next automatically sent packet
     */
    private NegotiatedAlgorithms guess() {
        if (!(peerKexAlgorithms.firstEqual(kexAlgorithms) &&
                peerHostKeyAlgorithms.firstEqual(hostKeyAlgorithms) &&
                peerC2SEncryptionAlgorithms.firstEqual(encryptionAlgorithms) &&
                peerS2CEncryptionAlgorithms.firstEqual(encryptionAlgorithms) &&
                peerC2SMacAlgorithms.firstEqual(macAlgorithms) &&
                peerS2CMacAlgorithms.firstEqual(macAlgorithms) &&
                peerC2SCompressionAlgorithms.firstEqual(compressionAlgorithms) &&
                peerS2CCompressionAlgorithms.firstEqual(compressionAlgorithms))
        )
            return null;

        NegotiatedAlgorithms result = new NegotiatedAlgorithms();

        result.kexAlgorithm = kexAlgorithms.getFirstNameWithId();
        result.hostKeyAlgorithm = hostKeyAlgorithms.getFirstNameWithId();
        result.sentEncryptionAlgorithm = encryptionAlgorithms.getFirstNameWithId();
        result.receivedEncryptionAlgorithm = encryptionAlgorithms.getFirstNameWithId();
        result.sentMacAlgorithm = macAlgorithms.getFirstNameWithId();
        result.receivedMacAlgorithm = macAlgorithms.getFirstNameWithId();
        result.sentCompressionAlgorithm = compressionAlgorithms.getFirstNameWithId();
        result.receivedCompressionAlgorithm = compressionAlgorithms.getFirstNameWithId();

        return result;
    }

    private NegotiatedAlgorithms calculateAlgorithms() {

        NegotiatedAlgorithms result = new NegotiatedAlgorithms();

        result.kexAlgorithm = kexAlgorithms.getFirstMatchingNameWithId(peerKexAlgorithms);
        result.hostKeyAlgorithm = hostKeyAlgorithms.getFirstMatchingNameWithId(peerHostKeyAlgorithms);
        result.sentEncryptionAlgorithm = sentNameWithId(encryptionAlgorithms, peerC2SEncryptionAlgorithms, peerS2CEncryptionAlgorithms);
        result.receivedEncryptionAlgorithm = receivedNameWithId(encryptionAlgorithms, peerC2SEncryptionAlgorithms, peerS2CEncryptionAlgorithms);
        result.sentMacAlgorithm = sentNameWithId(macAlgorithms, peerC2SMacAlgorithms, peerS2CMacAlgorithms);
        result.receivedMacAlgorithm = receivedNameWithId(macAlgorithms, peerC2SMacAlgorithms, peerS2CMacAlgorithms);
        result.sentCompressionAlgorithm = sentNameWithId(compressionAlgorithms, peerC2SCompressionAlgorithms, peerS2CCompressionAlgorithms);
        result.receivedCompressionAlgorithm = receivedNameWithId(compressionAlgorithms, peerC2SCompressionAlgorithms, peerS2CCompressionAlgorithms);

        return result.valid() ? result : null;
    }

    private NameWithId sentNameWithId(NameListWithIds own, NameListWithIds c2s, NameListWithIds s2c) {
        return own.getFirstMatchingNameWithId(side == Constant.CLIENT_SIDE ? s2c : c2s);
    }

    private NameWithId receivedNameWithId(NameListWithIds own, NameListWithIds c2s, NameListWithIds s2c) {
        return own.getFirstMatchingNameWithId(side == Constant.SERVER_SIDE ? s2c : c2s);
    }

    private static class NegotiatedAlgorithms {
        public NameWithId kexAlgorithm;
        public NameWithId hostKeyAlgorithm;
        public NameWithId sentEncryptionAlgorithm;
        public NameWithId receivedEncryptionAlgorithm;
        public NameWithId sentMacAlgorithm;
        public NameWithId receivedMacAlgorithm;
        public NameWithId sentCompressionAlgorithm;
        public NameWithId receivedCompressionAlgorithm;

        public boolean valid() {
            return (kexAlgorithm.valid(false)
                    && hostKeyAlgorithm.valid(false)
                    && sentEncryptionAlgorithm.valid(false)
                    && receivedEncryptionAlgorithm.valid(false)
                    && sentMacAlgorithm.valid(false)
                    && receivedMacAlgorithm.valid(false)
                    && sentCompressionAlgorithm.valid(true)
                    && receivedCompressionAlgorithm.valid(true)
            );
        }
    }

    public enum State {
        INITIAL,
        INITIAL_KEX_INIT_SENT,
        WAIT_FOR_OTHER_KEXINIT, // This side already sent a KEXINIT - as per RFC 2453 7.1
        DROP_GUESSED_PACKET,    // the next packet should be dropped
        AFTER_KEX,
        KEX,
    }
}
