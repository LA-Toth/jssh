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
            try {
                thread.join();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    public synchronized void startThread(SshThread r) {
        SshThreadPoolThread thread = SshThreadPoolThread.create(this, r);
        threads.add(thread);
        thread.start();
    }

    private static class SshThreadPoolThread extends Thread {
        SshThreadPool pool;
        SshThread runnable;

        private SshThreadPoolThread(SshThreadPool p, SshThread r) {
            pool = p;
            runnable = r;
        }

        public static SshThreadPoolThread create(SshThreadPool pool, SshThread runnable) {
            return new SshThreadPoolThread(pool, runnable);
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
