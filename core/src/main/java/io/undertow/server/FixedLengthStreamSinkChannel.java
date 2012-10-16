package io.undertow.server;


import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.FileChannel;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLongFieldUpdater;

import org.xnio.ChannelListener;
import org.xnio.ChannelListeners;
import org.xnio.Option;
import org.xnio.XnioExecutor;
import org.xnio.XnioWorker;
import org.xnio.channels.ConcurrentStreamChannelAccessException;
import org.xnio.channels.FixedLengthOverflowException;
import org.xnio.channels.FixedLengthUnderflowException;
import org.xnio.channels.ProtectedWrappedChannel;
import org.xnio.channels.StreamSinkChannel;
import org.xnio.channels.StreamSourceChannel;

import static java.lang.Math.min;
import static org.xnio.Bits.allAreClear;
import static org.xnio.Bits.allAreSet;
import static org.xnio.Bits.anyAreSet;
import static org.xnio.Bits.longBitMask;
import static org.xnio.IoUtils.safeClose;

/**
 * A channel which writes a fixed amount of data.  A listener is called once the data has been written.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class FixedLengthStreamSinkChannel implements StreamSinkChannel, ProtectedWrappedChannel<StreamSinkChannel> {
    private final StreamSinkChannel delegate;
    private final int config;
    private final Object guard;

    private final ChannelListener<? super FixedLengthStreamSinkChannel> finishListener;
    private final ChannelListener.SimpleSetter<FixedLengthStreamSinkChannel> writeSetter = new ChannelListener.SimpleSetter<FixedLengthStreamSinkChannel>();
    private final ChannelListener.SimpleSetter<FixedLengthStreamSinkChannel> closeSetter = new ChannelListener.SimpleSetter<FixedLengthStreamSinkChannel>();

    private long state;

    private static final int CONF_FLAG_CONFIGURABLE = 1 << 0;
    private static final int CONF_FLAG_PASS_CLOSE = 1 << 1;

    private static final long FLAG_WRITE_ENTERED = 1L << 63L;
    private static final long FLAG_CLOSE_REQUESTED = 1L << 62L;
    private static final long FLAG_CLOSE_COMPLETE = 1L << 61L;
    private static final long FLAG_SUS_RES_SHUT_ENTERED = 1L << 60L;
    private static final long MASK_COUNT = longBitMask(0, 58);

    /**
     * Construct a new instance.
     *
     * @param delegate       the delegate channel
     * @param contentLength  the content length
     * @param configurable   {@code true} if this instance should pass configuration to the delegate
     * @param propagateClose {@code true} if this instance should pass close to the delegate
     * @param finishListener the listener to call when the channel is closed or the length is reached
     * @param guard          the guard object to use
     */
    public FixedLengthStreamSinkChannel(final StreamSinkChannel delegate, final long contentLength, final boolean configurable, final boolean propagateClose, final ChannelListener<? super FixedLengthStreamSinkChannel> finishListener, final Object guard) {
        if (contentLength < 0L) {
            throw new IllegalArgumentException("Content length must be greater than or equal to zero");
        } else if (contentLength > MASK_COUNT) {
            throw new IllegalArgumentException("Content length is too long");
        }
        this.guard = guard;
        this.delegate = delegate;
        this.finishListener = finishListener;
        config = (configurable ? CONF_FLAG_CONFIGURABLE : 0) | (propagateClose ? CONF_FLAG_PASS_CLOSE : 0);
        this.state = contentLength;
        delegate.getWriteSetter().set(ChannelListeners.delegatingChannelListener(this, writeSetter));
    }

    public ChannelListener.Setter<? extends StreamSinkChannel> getWriteSetter() {
        return writeSetter;
    }

    public ChannelListener.Setter<? extends StreamSinkChannel> getCloseSetter() {
        return closeSetter;
    }

    public StreamSinkChannel getChannel(final Object guard) {
        final Object ourGuard = this.guard;
        if (ourGuard == null || guard == ourGuard) {
            return delegate;
        } else {
            return null;
        }
    }

    public XnioExecutor getWriteThread() {
        return delegate.getWriteThread();
    }

    public XnioWorker getWorker() {
        return delegate.getWorker();
    }

    public int write(final ByteBuffer src) throws IOException {
        if (!src.hasRemaining()) {
            return 0;
        }
        long val = enterWrite();
        if (allAreSet(val, FLAG_CLOSE_REQUESTED)) {
            throw new ClosedChannelException();
        }
        if (allAreClear(val, MASK_COUNT)) {
            throw new FixedLengthOverflowException();
        }
        int res = 0;
        final long remaining = val & MASK_COUNT;
        try {
            final int lim = src.limit();
            final int pos = src.position();
            if (lim - pos > remaining) {
                src.limit((int) (remaining - (long) pos));
                try {
                    return res = delegate.write(src);
                } finally {
                    src.limit(lim);
                }
            } else {
                return res = delegate.write(src);
            }
        } finally {
            exitWrite(val, (long) res);
        }
    }

    public long write(final ByteBuffer[] srcs) throws IOException {
        return write(srcs, 0, srcs.length);
    }

    public long write(final ByteBuffer[] srcs, final int offset, final int length) throws IOException {
        if (length == 0) {
            return 0L;
        } else if (length == 1) {
            return write(srcs[offset]);
        }
        long val = enterWrite();
        if (allAreSet(val, FLAG_CLOSE_REQUESTED)) {
            throw new ClosedChannelException();
        }
        if (allAreClear(val, MASK_COUNT)) {
            throw new FixedLengthOverflowException();
        }
        long res = 0L;
        try {
            if ((val & MASK_COUNT) == 0L) {
                return -1L;
            }
            int lim;
            // The total amount of buffer space discovered so far.
            long t = 0L;
            for (int i = 0; i < length; i++) {
                final ByteBuffer buffer = srcs[i + offset];
                // Grow the discovered buffer space by the remaining size of the current buffer.
                // We want to capture the limit so we calculate "remaining" ourselves.
                t += (lim = buffer.limit()) - buffer.position();
                if (t > (val & MASK_COUNT)) {
                    // only read up to this point, and trim the last buffer by the number of extra bytes
                    buffer.limit(lim - (int) (t - (val & MASK_COUNT)));
                    try {
                        return res = delegate.write(srcs, offset, i + 1);
                    } finally {
                        // restore the original limit
                        buffer.limit(lim);
                    }
                }
            }
            if (t == 0L) {
                return 0L;
            }
            // the total buffer space is less than the remaining count.
            return res = delegate.write(srcs, offset, length);
        } finally {
            exitWrite(val, res);
        }
    }

    public long transferFrom(final FileChannel src, final long position, final long count) throws IOException {
        if (count == 0L) return 0L;
        long val = enterWrite();
        if (allAreSet(val, FLAG_CLOSE_REQUESTED)) {
            throw new ClosedChannelException();
        }
        if (allAreClear(val, MASK_COUNT)) {
            throw new FixedLengthOverflowException();
        }
        long res = 0L;
        try {
            return res = delegate.transferFrom(src, position, min(count, (val & MASK_COUNT)));
        } finally {
            exitWrite(val, res);
        }
    }

    public long transferFrom(final StreamSourceChannel source, final long count, final ByteBuffer throughBuffer) throws IOException {
        if (count == 0L) return 0L;
        long val = enterWrite();
        if (allAreSet(val, FLAG_CLOSE_REQUESTED)) {
            throw new ClosedChannelException();
        }
        if (allAreClear(val, MASK_COUNT)) {
            throw new FixedLengthOverflowException();
        }
        long res = 0L;
        try {
            return res = delegate.transferFrom(source, min(count, (val & MASK_COUNT)), throughBuffer);
        } finally {
            exitWrite(val, res);
        }
    }

    public boolean flush() throws IOException {
        long val = enterFlush();
        if (anyAreSet(val, FLAG_CLOSE_COMPLETE)) {
            return true;
        }
        if (anyAreSet(val, FLAG_WRITE_ENTERED)) {
            return false;
        }
        boolean flushed = false;
        try {
            return flushed = delegate.flush();
        } finally {
            exitFlush(val, flushed);
        }
    }

    public void suspendWrites() {
        long val = enterSuspendResume();
        if (anyAreSet(val, FLAG_CLOSE_COMPLETE | FLAG_SUS_RES_SHUT_ENTERED)) {
            return;
        }
        try {
            delegate.suspendWrites();
        } finally {
            exitSuspendResume(val);
        }
    }

    public void resumeWrites() {
        long val = enterSuspendResume();
        if (anyAreSet(val, FLAG_CLOSE_COMPLETE | FLAG_SUS_RES_SHUT_ENTERED)) {
            return;
        }
        try {
            delegate.resumeWrites();
        } finally {
            exitSuspendResume(val);
        }
    }

    public boolean isWriteResumed() {
        // not perfect but not provably wrong either...
        return allAreClear(state, FLAG_CLOSE_COMPLETE) && delegate.isWriteResumed();
    }

    public void wakeupWrites() {
        long val = enterSuspendResume();
        if (anyAreSet(val, FLAG_CLOSE_COMPLETE | FLAG_SUS_RES_SHUT_ENTERED)) {
            return;
        }
        try {
            delegate.wakeupWrites();
        } finally {
            exitSuspendResume(val);
        }
    }

    public void shutdownWrites() throws IOException {
        final long val = enterShutdown();
        try {
            if (anyAreSet(val, MASK_COUNT)) try {
                throw new FixedLengthUnderflowException((val & MASK_COUNT) + " bytes remaining");
            } finally {
                if (allAreSet(config, CONF_FLAG_PASS_CLOSE)) {
                    safeClose(delegate);
                }
            }
            else if (allAreSet(config, CONF_FLAG_PASS_CLOSE)) {
                delegate.shutdownWrites();
            }
        } finally {
            exitShutdown(val);
        }
    }

    public void awaitWritable() throws IOException {
        delegate.awaitWritable();
    }

    public void awaitWritable(final long time, final TimeUnit timeUnit) throws IOException {
        delegate.awaitWritable(time, timeUnit);
    }

    public boolean isOpen() {
        return allAreClear(state, FLAG_CLOSE_REQUESTED);
    }

    public void close() throws IOException {
        final long val = enterClose();
        try {
            if (anyAreSet(val, MASK_COUNT)) try {
                throw new FixedLengthUnderflowException((val & MASK_COUNT) + " bytes remaining");
            } finally {
                if (allAreSet(config, CONF_FLAG_PASS_CLOSE)) {
                    safeClose(delegate);
                }
            }
            else if (allAreSet(config, CONF_FLAG_PASS_CLOSE)) {
                delegate.close();
            }
        } finally {
            exitClose(val);
        }
    }

    public boolean supportsOption(final Option<?> option) {
        return allAreSet(config, CONF_FLAG_CONFIGURABLE) && delegate.supportsOption(option);
    }

    public <T> T getOption(final Option<T> option) throws IOException {
        return allAreSet(config, CONF_FLAG_CONFIGURABLE) ? delegate.getOption(option) : null;
    }

    public <T> T setOption(final Option<T> option, final T value) throws IllegalArgumentException, IOException {
        return allAreSet(config, CONF_FLAG_CONFIGURABLE) ? delegate.setOption(option, value) : null;
    }

    /**
     * Get the number of remaining bytes in this fixed length channel.
     *
     * @return the number of remaining bytes
     */
    public long getRemaining() {
        return state & MASK_COUNT;
    }

    private long enterWrite() {
        long oldVal, newVal;
        oldVal = state;
        if (allAreSet(oldVal, FLAG_CLOSE_COMPLETE) || allAreClear(oldVal, MASK_COUNT)) {
            // do not swap
            return oldVal;
        }
        if (allAreSet(oldVal, FLAG_WRITE_ENTERED)) {
            throw new ConcurrentStreamChannelAccessException();
        }
        newVal = oldVal | FLAG_WRITE_ENTERED;
        this.state = newVal;
        return oldVal;
    }

    private void exitWrite(long oldVal, long consumed) {
        long newVal = oldVal - consumed;
        this.state = newVal;
        if (allAreSet(newVal, FLAG_SUS_RES_SHUT_ENTERED)) {
            // don't call listener while other shit is in flight
            return;
        }
        if (allAreSet(newVal, FLAG_CLOSE_COMPLETE)) {
            // closed while we were in flight.  Call the listener.
            callClosed();
            callFinish();
        }
    }

    private long enterFlush() {
        long oldVal, newVal;
        oldVal = state;
        if (anyAreSet(oldVal, FLAG_CLOSE_COMPLETE | FLAG_WRITE_ENTERED)) {
            // do not swap
            return oldVal;
        }
        newVal = oldVal | FLAG_WRITE_ENTERED;
        this.state = newVal;
        return oldVal;
    }

    private void exitFlush(long oldVal, boolean flushed) {
        long newVal = oldVal;
        if (anyAreSet(oldVal, FLAG_CLOSE_REQUESTED)) {
            newVal |= FLAG_CLOSE_COMPLETE;
        }
        this.state = newVal;
        if (allAreSet(newVal, FLAG_SUS_RES_SHUT_ENTERED)) {
            // don't call listener while other shit is in flight
            return;
        }
        if (allAreSet(newVal, FLAG_CLOSE_COMPLETE)) {
            // closed while we were in flight or by us.
            callClosed();
        }
        if (anyAreSet(oldVal, MASK_COUNT) && allAreClear(newVal, MASK_COUNT)) {
            callFinish();
        }
    }

    private long enterSuspendResume() {
        long oldVal, newVal;
        oldVal = state;
        if (anyAreSet(oldVal, FLAG_CLOSE_COMPLETE | FLAG_SUS_RES_SHUT_ENTERED)) {
            return oldVal;
        }
        newVal = oldVal | FLAG_SUS_RES_SHUT_ENTERED;
        this.state = newVal;
        return oldVal;
    }

    private void exitSuspendResume(long oldVal) {
        final boolean wasClosed = allAreClear(oldVal, FLAG_CLOSE_COMPLETE);
        final boolean wasEntered = allAreSet(oldVal, FLAG_WRITE_ENTERED);
        long newVal = oldVal & ~FLAG_SUS_RES_SHUT_ENTERED;
        this.state = newVal;
        if (!wasEntered) {
            if (!wasClosed && allAreSet(newVal, FLAG_CLOSE_COMPLETE)) {
                callFinish();
                callClosed();
            }
        }
    }

    private long enterShutdown() {
        long oldVal, newVal;
        oldVal = state;
        if (anyAreSet(oldVal, FLAG_CLOSE_REQUESTED | FLAG_CLOSE_COMPLETE)) {
            // no action necessary
            return oldVal;
        }
        newVal = oldVal | FLAG_SUS_RES_SHUT_ENTERED | FLAG_CLOSE_REQUESTED;
        if (anyAreSet(oldVal, MASK_COUNT)) {
            // error: channel not filled.  set both close flags.
            newVal |= FLAG_CLOSE_COMPLETE;
        }
        this.state = newVal;
        return oldVal;
    }

    private void exitShutdown(long oldVal) {
        final boolean wasInSusRes = allAreSet(oldVal, FLAG_SUS_RES_SHUT_ENTERED);
        final boolean wasEntered = allAreSet(oldVal, FLAG_WRITE_ENTERED);
        if (!wasInSusRes) {
            long newVal = oldVal & ~FLAG_SUS_RES_SHUT_ENTERED;
            this.state = newVal;
            if (!wasEntered) {
                callFinish();
                callClosed();
            }
        }
        // else let exitSuspendResume/exitWrite handle this
    }

    private long enterClose() {
        long oldVal, newVal;
        oldVal = state;
        if (anyAreSet(oldVal, FLAG_CLOSE_COMPLETE)) {
            // no action necessary
            return oldVal;
        }
        newVal = oldVal | FLAG_SUS_RES_SHUT_ENTERED | FLAG_CLOSE_REQUESTED | FLAG_CLOSE_COMPLETE;
        if (anyAreSet(oldVal, MASK_COUNT)) {
            // error: channel not filled.  set both close flags.
            newVal |= FLAG_CLOSE_REQUESTED | FLAG_CLOSE_COMPLETE;
        }
        this.state = newVal;
        return oldVal;
    }

    private void exitClose(long oldVal) {
        final boolean wasInSusRes = allAreSet(oldVal, FLAG_SUS_RES_SHUT_ENTERED);
        final boolean wasEntered = allAreSet(oldVal, FLAG_WRITE_ENTERED);
        if (!wasInSusRes) {
            long newVal = oldVal & ~FLAG_SUS_RES_SHUT_ENTERED;
            this.state = newVal;
            if (!wasEntered) {
                callFinish();
                callClosed();
            }
        }
        // else let exitSuspendResume/exitWrite handle this
    }

    private void callFinish() {
        ChannelListeners.invokeChannelListener(this, finishListener);
    }

    private void callClosed() {
        ChannelListeners.invokeChannelListener(this, closeSetter.get());
    }
}
