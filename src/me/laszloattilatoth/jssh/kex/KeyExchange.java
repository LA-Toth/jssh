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
    private final State state = State.INITIAL;
    private final KexInitPacket ownInitPacket = new KexInitPacket();
    private KexInitPacket peerInitPacket;

    private NameWithId kexName;
    private NameWithId hostKeyAlg;

    private final NewKeys[] newKeys = new NewKeys[Constant.MODE_MAX];

    public KeyExchange(TransportLayer transportLayer) {
        this.transportLayer = new WeakReference<>(transportLayer);
        this.config = transportLayer.getConfig();
        this.side = transportLayer.side;
        this.logger = transportLayer.getLogger();

        try {
            this.ownInitPacket.set(KexInitEntries.ENTRY_KEX_ALGOS, NameListWithIds.create(Util.getConfigValueBySide(this.config, this.side, "kex_algorithms")));
            this.ownInitPacket.set(KexInitEntries.ENTRY_SERVER_HOST_KEY_ALG, NameListWithIds.create(Util.getConfigValueBySide(this.config, this.side, "hostkey_algorithms")));
            this.ownInitPacket.set(KexInitEntries.ENTRY_ENC_ALGOS_C2S, NameListWithIds.create(Util.getConfigValueBySide(this.config, this.side, "encryption_algorithms")));
            this.ownInitPacket.set(KexInitEntries.ENTRY_ENC_ALGOS_S2C, this.ownInitPacket.get(KexInitEntries.ENTRY_ENC_ALGOS_C2S));
            this.ownInitPacket.set(KexInitEntries.ENTRY_MAC_ALGOS_C2S, NameListWithIds.create(Util.getConfigValueBySide(this.config, this.side, "mac_algorithms")));
            this.ownInitPacket.set(KexInitEntries.ENTRY_MAC_ALGOS_S2C, this.ownInitPacket.get(KexInitEntries.ENTRY_MAC_ALGOS_C2S));
            this.ownInitPacket.set(KexInitEntries.ENTRY_COMP_ALGOS_C2S, NameListWithIds.create(Util.getConfigValueBySide(this.config, this.side, "compression_algorithms")));
            this.ownInitPacket.set(KexInitEntries.ENTRY_COMP_ALGOS_S2C, this.ownInitPacket.get(KexInitEntries.ENTRY_COMP_ALGOS_C2S));
        } catch (KexException e) {
            // cannot happen. FIXME.
        }
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

    public String sideStr() {
        return isClientSide() ? "client" : "server";
    }

    public void sendInitialMsgKexInit() throws KexException {
        Packet packet = new Packet();
        try {
            ownInitPacket.writeToPacket(packet);
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
        peerInitPacket = initPacket;
        chooseAlgos();
    }

    // Validated/partially based on OpenSSH kex.c: kex_choose_conf
    private void chooseAlgos() throws KexException {
        KexInitEntries client = isClientSide() ? peerInitPacket : ownInitPacket;
        KexInitEntries server = isClientSide() ? ownInitPacket : peerInitPacket;

        // not checking ext_info_c - RFC 8308

        // Choose all algos one by one, and throw exception if no matching algo
        this.kexName = chooseAlg(client, server, KexInitEntries.ENTRY_KEX_ALGOS, "No matching KEX algorithm");
        this.hostKeyAlg = chooseAlg(client, server, KexInitEntries.ENTRY_SERVER_HOST_KEY_ALG, "No matching HostKey algorithm");

        for (int mode = Constant.MODE_IN; mode != Constant.MODE_MAX; ++mode) {
            boolean c2s = (isClientSide() && mode == Constant.MODE_IN) || (isServerSide() && mode == Constant.MODE_OUT);
            int encIdx = c2s ? KexInitEntries.ENTRY_ENC_ALGOS_C2S : KexInitEntries.ENTRY_ENC_ALGOS_S2C;
            int macIdx = c2s ? KexInitEntries.ENTRY_MAC_ALGOS_C2S : KexInitEntries.ENTRY_MAC_ALGOS_S2C;
            int compIdx = c2s ? KexInitEntries.ENTRY_COMP_ALGOS_C2S : KexInitEntries.ENTRY_COMP_ALGOS_S2C;

            NewKeys newkeys = new NewKeys();
            this.newKeys[mode] = newkeys;
            chooseEncAlg(newkeys, client, server, encIdx);
            if (newkeys.cipherAuthLen() == 0)
                chooseMacAlg(newkeys, client, server, macIdx);
            chooseCompAlg(newkeys, client, server, compIdx);

            logger.fine(() -> String.format("KEX algo match; kex='%s', cipher='%s', MAC='%s', compression='%s', direction='%s', side='%s'",
                    kexName.getName(),
                    newkeys.enc.name(),
                    newkeys.mac.name(),
                    "none", // FIXME
                    c2s ? "client->server" : "server->client",
                    sideStr()
            ));
        }

    }

    private NameWithId chooseAlg(KexInitEntries client, KexInitEntries server, int index, String exceptionString) throws KexException {
        return matchList(client.entries[index], server.entries[index], exceptionString);
    }

    private NameWithId matchList(NameListWithIds client, NameListWithIds server, String exceptionString) throws KexException {
        int nameId = server.getFirstMatchingId(client);
        if (nameId == Name.SSH_NAME_UNKNOWN) {
            logger.severe(() -> String.format("KEX algo list mismatch; error='%s', own='%s', peer='%s', side='%s'",
                    exceptionString,
                    isClientSide() ? server.getNameList() : client.getNameList(),
                    isServerSide() ? server.getNameList() : client.getNameList(),
                    sideStr()
            ));
            throw new KexException(exceptionString);
        }

        return new NameWithId(nameId);
    }

    private void chooseEncAlg(NewKeys newKeys, KexInitEntries client, KexInitEntries server, int index) throws KexException {
        NameWithId encAlg = chooseAlg(client, server, index, "No matching Encryption algorithm");
        newKeys.setEncryption(encAlg);
    }

    private void chooseMacAlg(NewKeys newKeys, KexInitEntries client, KexInitEntries server, int index) throws KexException {
        NameWithId macAlg = chooseAlg(client, server, index, "No matching MAC algorithm");
        newKeys.setMac(macAlg);
    }

    private void chooseCompAlg(NewKeys newKeys, KexInitEntries client, KexInitEntries server, int index) throws KexException {
        NameWithId compAlg = chooseAlg(client, server, index, "No matching Compression algorithm");
        newKeys.setCompression(compAlg);
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
