package me.laszloattilatoth.jssh.kex;

import me.laszloattilatoth.jssh.Config;
import me.laszloattilatoth.jssh.Util;
import me.laszloattilatoth.jssh.proxy.*;
import me.laszloattilatoth.jssh.transportlayer.TransportLayer;
import me.laszloattilatoth.jssh.transportlayer.TransportLayerException;

import java.io.IOException;
import java.lang.ref.WeakReference;
import java.util.Objects;
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
    private NameListWithIds[] ownAlgos;
    private NameListWithIds[] peerAlgos;

    private NameWithId name;

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

    public boolean isClientSide() {
        return side == Constant.CLIENT_SIDE;
    }

    public boolean isServerSide() {
        return side == Constant.SERVER_SIDE;
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

        try {
            Objects.requireNonNull(transportLayer.get()).writePacket(packet);
        } catch (IOException e) {
            logger.severe(() -> String.format("Unable to send SSH_MSG_KEXINIT; error='%s'", e.getMessage()));
            throw new KexException(e.getMessage());
        }
    }

    /// RFC 4253 7.1.  Algorithm Negotiation (SSH_MSG_KEXINIT)
    public void processMsgKexInit(Packet packet) throws TransportLayerException {
        Objects.requireNonNull(transportLayer.get()).unregisterHandler(Constant.SSH_MSG_KEXINIT);

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

        // TODO: rekeying -send our own kex packet
        // TODO: not always save peer packet
        // peerInitPacket = initPacket;
    }

    private void calculateAlgos() throws KexException {
        NameListWithIds[] client = isClientSide() ? peerAlgos : ownAlgos;
        NameListWithIds[] server = isServerSide() ? ownAlgos : peerAlgos;

        calculateKex(client[KexInitPacket.ENTRY_KEX_ALGOS], server[KexInitPacket.ENTRY_KEX_ALGOS]);
    }

    private void calculateKex(NameListWithIds client, NameListWithIds server) throws KexException {
        int nameId = client.getFirstMatchingId(server);
        if (nameId == Name.SSH_NAME_UNKNOWN) {
            throw new KexException("TODO"); // TODO: xxx
        }
        name = new NameWithId(nameId);
        logger.info(name.getName());
        //kexalg = kex_alg_by_name(name);

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
