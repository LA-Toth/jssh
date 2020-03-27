package me.laszloattilatoth.jssh.threading;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class SshThreadPool {
    private int maxThreads;
    private List<Thread> threads = new ArrayList<>();
    private List<Thread> finishedThreads = new ArrayList<>();

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
                    e.printStackTrace();
                } catch(IllegalMonitorStateException e) {
                    e.printStackTrace();
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

    private static class SshThreadPoolThread extends Thread {
        private SshThreadPool pool;
        private SshThread runnable;
        private static int lastThreadId = 0;

        private SshThreadPoolThread(int threadId, SshThreadPool p, SshThread r) {
            super("SshThread-in-pool." + String.valueOf(threadId));
            pool = p;
            runnable = r;
        }

        public synchronized static SshThreadPoolThread create(SshThreadPool pool, SshThread runnable) {
            lastThreadId += 1;
            return new SshThreadPoolThread(lastThreadId, pool, runnable);
        }

        public void run() {
            try {
                runnable.run();
            } finally {
                try {
                    runnable.socket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                pool.finishThread(this);
            }
        }
    }
}
