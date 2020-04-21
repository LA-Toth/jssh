package me.laszloattilatoth.jssh.threading;

import me.laszloattilatoth.jssh.Util;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class SshThreadPool {
    private final int maxThreads;
    private final List<Thread> threads = new ArrayList<>();
    private final List<Thread> finishedThreads = new ArrayList<>();

    public SshThreadPool(int maxThreads) {
        this.maxThreads = maxThreads;
    }

    public synchronized int activeThreadCount() {
        return threads.size();
    }

    public synchronized boolean full() {
        return threads.size() == maxThreads;
    }

    public synchronized boolean canStartThread() {
        return threads.size() != maxThreads;
    }

    public synchronized void finishThread(SshThreadPoolThread thread) {
        finishedThreads.add(thread);
        threads.remove(thread);
    }

    public synchronized void cleanup() {
        while (finishedThreads.size() > 0) {
            Thread thread = finishedThreads.get(0);
            if (thread.isAlive()) {
                try {
                    thread.wait();
                } catch (InterruptedException e) {
                    Util.logExceptionWithBacktrace(Logger.getGlobal(), e, Level.SEVERE);
                }
            }
            if (!thread.isAlive()) {
                finishedThreads.remove(thread);
            }
        }
    }

    public synchronized void startThread(SshThread r) {
        SshThreadPoolThread thread = SshThreadPoolThread.create(this, r);
        threads.add(thread);
        thread.start();
    }

    public static class SshThreadPoolThread extends Thread {
        private final SshThreadPool pool;
        private final SshThread sshThread;
        private final Logger logger;

        private SshThreadPoolThread(SshThreadPool p, SshThread thread) {
            super(thread.getName());
            this.pool = p;
            this.sshThread = thread;
            this.logger = thread.logger;
        }

        public synchronized static SshThreadPoolThread create(SshThreadPool pool, SshThread thread) {
            return new SshThreadPoolThread(pool, thread);
        }

        public Logger logger() {
            return logger;
        }

        public void run() {
            try {
                sshThread.run();
            } finally {
                try {
                    sshThread.socket.close();
                } catch (IOException e) {
                    logger.severe("Unable to close socket of the SSH thread;");
                    Util.logException(logger, e, Level.SEVERE);
                }
                pool.finishThread(this);
            }
        }
    }
}
