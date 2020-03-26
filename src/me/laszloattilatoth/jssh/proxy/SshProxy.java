package me.laszloattilatoth.jssh.proxy;

import me.laszloattilatoth.jssh.Config;
import me.laszloattilatoth.jssh.threading.SshThread;

import java.io.*;
import java.net.Socket;
import java.util.Date;

public class SshProxy extends SshThread {
    public SshProxy(Config config, Socket s, InputStream is, OutputStream os) {
        super(config, s, is, os);
    }

    @Override
    public void run() {
        try {
            Writer out = new OutputStreamWriter(outputStream);
            Date now = new Date();
            out.write(now.toString() + "\r\n");
            out.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }

//        throw new NullPointerException("whaterver");
    }
}
