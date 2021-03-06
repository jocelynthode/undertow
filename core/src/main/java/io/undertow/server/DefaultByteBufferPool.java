/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package io.undertow.server;

import io.undertow.UndertowMessages;
import io.undertow.connector.ByteBufferPool;
import io.undertow.connector.PooledByteBuffer;

import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;

/**
 * A byte buffer pool that supports reference counted pools.
 *
 * TODO: move this somewhere more appropriate
 *
 * @author Stuart Douglas
 */
public class DefaultByteBufferPool implements ByteBufferPool {

    private final ThreadLocal<ThreadLocalData> threadLocalCache = new ThreadLocal<>();
    private final List<ThreadLocalData> threadLocalDataList = Collections.synchronizedList(new ArrayList<ThreadLocalData>());
    private final ConcurrentLinkedQueue<ByteBuffer> queue = new ConcurrentLinkedQueue<>();

    private final boolean direct;
    private final int bufferSize;
    private final int maximumPoolSize;
    private final int threadLocalCacheSize;
    private final int leakDectionPercent;
    private int count; //racily updated count used in leak detection

    @SuppressWarnings("unused")
    private volatile int currentQueueLength = 0;
    private static final AtomicIntegerFieldUpdater<DefaultByteBufferPool> currentQueueLengthUpdater = AtomicIntegerFieldUpdater.newUpdater(DefaultByteBufferPool.class, "currentQueueLength");

    private volatile boolean closed;


    /**
     * @param direct               If this implementation should use direct buffers
     * @param bufferSize           The buffer size to use
     */
    public DefaultByteBufferPool(boolean direct, int bufferSize) {
        this(direct, bufferSize, -1, 12, 0);
    }
    /**
     * @param direct               If this implementation should use direct buffers
     * @param bufferSize           The buffer size to use
     * @param maximumPoolSize      The maximum pool size, in number of buffers, it does not include buffers in thread local caches
     * @param threadLocalCacheSize The maximum number of buffers that can be stored in a thread local cache
     */
    public DefaultByteBufferPool(boolean direct, int bufferSize, int maximumPoolSize, int threadLocalCacheSize, int leakDecetionPercent) {
        this.direct = direct;
        this.bufferSize = bufferSize;
        this.maximumPoolSize = maximumPoolSize;
        this.threadLocalCacheSize = threadLocalCacheSize;
        this.leakDectionPercent = leakDecetionPercent;
    }


    /**
     * @param direct               If this implementation should use direct buffers
     * @param bufferSize           The buffer size to use
     * @param maximumPoolSize      The maximum pool size, in number of buffers, it does not include buffers in thread local caches
     * @param threadLocalCacheSize The maximum number of buffers that can be stored in a thread local cache
     */
    public DefaultByteBufferPool(boolean direct, int bufferSize, int maximumPoolSize, int threadLocalCacheSize) {
        this(direct, bufferSize, maximumPoolSize, threadLocalCacheSize, 0);
    }

    @Override
    public int getBufferSize() {
        return bufferSize;
    }

    @Override
    public PooledByteBuffer allocate() {
        if (closed) {
            throw UndertowMessages.MESSAGES.poolIsClosed();
        }
        ByteBuffer buffer = null;
        ThreadLocalData local = null;
        if(threadLocalCacheSize > 0) {
            local = threadLocalCache.get();
            if (local != null) {
                buffer = local.buffers.poll();
                if (buffer != null) {
                    currentQueueLengthUpdater.decrementAndGet(this);
                }
            } else {
                local = new ThreadLocalData();
                threadLocalCache.set(local);
                threadLocalDataList.add(local);
            }
        }
        if (buffer == null) {
            buffer = queue.poll();
        }
        if (buffer == null) {
            if (direct) {
                buffer = ByteBuffer.allocateDirect(bufferSize);
            } else {
                buffer = ByteBuffer.allocate(bufferSize);
            }
        }
        if(local != null) {
            local.allocationDepth++;
        }
        buffer.clear();
        return new DefaultPooledBuffer(this, buffer, leakDectionPercent == 0 ? false : (++count % 100 > leakDectionPercent));
    }

    private void freeInternal(ByteBuffer buffer) {
        if (closed) {
            return; //GC will take care of it
        }
        ThreadLocalData local = threadLocalCache.get();
        if(local != null) {
            if(local.allocationDepth > 0) {
                local.allocationDepth--;
                if (local.buffers.size() < threadLocalCacheSize) {
                    local.buffers.add(buffer);
                    return;
                }
            }
        }
        int size;
        do {
            size = currentQueueLength;
            if(size > maximumPoolSize) {
                return;
            }
        } while (!currentQueueLengthUpdater.compareAndSet(this, size, currentQueueLength + 1));
        queue.add(buffer);
    }

    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        queue.clear();
        for(ThreadLocalData local : threadLocalDataList) {
            local.buffers.clear();
        }
    }

    @Override
    protected void finalize() throws Throwable {
        super.finalize();
        close();
    }

    private static class DefaultPooledBuffer implements PooledByteBuffer {

        private final DefaultByteBufferPool pool;
        private final LeakDetector leakDetector;
        private ByteBuffer buffer;

        private volatile int referenceCount = 1;
        private static final AtomicIntegerFieldUpdater<DefaultPooledBuffer> referenceCountUpdater = AtomicIntegerFieldUpdater.newUpdater(DefaultPooledBuffer.class, "referenceCount");



        public DefaultPooledBuffer(DefaultByteBufferPool pool, ByteBuffer buffer, boolean detectLeaks) {
            this.pool = pool;
            this.buffer = buffer;
            this.leakDetector = detectLeaks ? new LeakDetector() : null;
        }

        @Override
        public ByteBuffer getBuffer() {
            if(referenceCount == 0) {
                throw UndertowMessages.MESSAGES.bufferAlreadyFreed();
            }
            return buffer;
        }

        @Override
        public void close() {
            if(referenceCountUpdater.compareAndSet(this, 1, 0)) {
                if(leakDetector != null) {
                    leakDetector.closed = true;
                }
                pool.freeInternal(buffer);
                this.buffer = null;
            }
        }

        @Override
        public boolean isOpen() {
            return referenceCount > 0;
        }

        @Override
        public String toString() {
            return "DefaultPooledBuffer{" +
                    "buffer=" + buffer +
                    ", referenceCount=" + referenceCount +
                    '}';
        }
    }

    private class ThreadLocalData {
        ArrayDeque<ByteBuffer> buffers = new ArrayDeque<>(threadLocalCacheSize);
        int allocationDepth = 0;
    }

    private static class LeakDetector {

        volatile boolean closed = false;
        private final Throwable allocationPoint;

        private LeakDetector() {
            this.allocationPoint = new Throwable("Buffer leak detected");
        }

        @Override
        protected void finalize() throws Throwable {
            super.finalize();
            if(!closed) {
                allocationPoint.printStackTrace();
            }
        }
    }

}
