import android.content.Context;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.os.ProxyFileDescriptorCallback;
import android.os.storage.StorageManager;
import android.system.ErrnoException;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;

public class FuseStall {
    static final int PAGE = 4096;
    static final int FILE_SIZE = PAGE * 64;
    static volatile boolean release;

    static void log(String s) {
        System.out.println("[fuse] " + s);
        System.out.flush();
        try {
            FileOutputStream fos = new FileOutputStream("/data/local/tmp/fusestall.log", true);
            fos.write((s + "\n").getBytes(StandardCharsets.UTF_8));
            fos.close();
        } catch (Exception ignored) {}
    }

    static Context systemContext() throws Exception {
        Class<?> at = Class.forName("android.app.ActivityThread");
        Method systemMain = at.getMethod("systemMain");
        Object thread = systemMain.invoke(null);
        Method getSystemContext = at.getMethod("getSystemContext");
        return (Context) getSystemContext.invoke(thread);
    }

    static class Cb extends ProxyFileDescriptorCallback {
        public long onGetSize() { return FILE_SIZE; }
        public int onRead(long offset, int size, byte[] data) throws ErrnoException {
            boolean armed = new File("/data/local/tmp/fusestall.arm").exists();
            log("onRead off=" + offset + " size=" + size + " armed=" + armed);
            boolean hits_stall = (offset + size) > (PAGE * 8);
            if (armed && hits_stall) {
                if (!new File("/data/local/tmp/fusestall.release").exists())
                    release = false;
                log("stall onRead covering off=" + offset + " size=" + size + " sticky=" + release);
                long start = System.nanoTime();
                while (!release && System.nanoTime() - start < 20000000000L) {
                    try { Thread.sleep(10); } catch (InterruptedException ignored) {}
                    if (new File("/data/local/tmp/fusestall.release").exists()) release = true;
                }
                log("released after_ms=" + ((System.nanoTime() - start) / 1e6));
            }
            int n = Math.min(size, FILE_SIZE - (int) offset);
            if (n < 0) n = 0;
            for (int i = 0; i < n; i++) data[i] = 0;
            return n;
        }
        public int onWrite(long offset, int size, byte[] data) { return size; }
        public void onFsync() {}
        public void onRelease() { log("onRelease"); }
    }

    static void sendFd(FileDescriptor fd) throws Exception {
        LocalSocket sock = new LocalSocket();
        sock.connect(new LocalSocketAddress("e1c3fuse"));
        sock.setFileDescriptorsForSend(new FileDescriptor[] { fd });
        sock.getOutputStream().write(1);
        sock.getOutputStream().flush();
        log("sent fd over abstract socket");
        try { Thread.sleep(500); } catch (InterruptedException ignored) {}
        sock.close();
    }

    public static void main(String[] args) {
        try {
            new File("/data/local/tmp/fusestall.log").delete();
            log("start pid=" + android.os.Process.myPid() + " uid=" + android.os.Process.myUid());
            HandlerThread ht = new HandlerThread("fuse-stall");
            ht.start();
            Looper.prepareMainLooper();
            Context ctx = systemContext();
            log("context=" + ctx);
            StorageManager sm = (StorageManager) ctx.getSystemService(Context.STORAGE_SERVICE);
            log("sm=" + sm);
            ParcelFileDescriptor pfd = sm.openProxyFileDescriptor(
                    ParcelFileDescriptor.MODE_READ_WRITE, new Cb(), new Handler(ht.getLooper()));
            int nfd = pfd.getFd();
            log("READY pid=" + android.os.Process.myPid() + " fd=" + nfd);
            sendFd(pfd.getFileDescriptor());
            long start = System.nanoTime();
            while (System.nanoTime() - start < 180000000000L) {
                if (new File("/data/local/tmp/fusestall.quit").exists()) break;
                try { Thread.sleep(100); } catch (InterruptedException ignored) {}
            }
            try { pfd.close(); } catch (Exception ignored) {}
            log("exit");
        } catch (Throwable t) {
            t.printStackTrace();
            log("FAIL " + t);
        }
    }
}
