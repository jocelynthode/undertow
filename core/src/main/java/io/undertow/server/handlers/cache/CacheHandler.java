package io.undertow.server.handlers.cache;

import io.undertow.server.ConduitWrapper;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.HttpHandlers;
import io.undertow.server.handlers.ResponseCodeHandler;
import io.undertow.util.ConduitFactory;
import org.xnio.conduits.StreamSinkConduit;

import static io.undertow.util.Headers.CONTENT_LENGTH;

/**
 *
 * Handler that attaches a cache to the exchange, a handler can query this cache to see if the
 * cache has a cached copy of the content, and if so have the cache serve this content automatically.
 *
 *
 * @author Stuart Douglas
 */
public class CacheHandler implements HttpHandler {

    private final DirectBufferCache<CachedHttpRequest> cache;
    private volatile HttpHandler next = ResponseCodeHandler.HANDLE_404;

    public CacheHandler(final DirectBufferCache<CachedHttpRequest> cache, final HttpHandler next) {
        this.cache = cache;
        this.next = next;
    }

    public CacheHandler(final DirectBufferCache<CachedHttpRequest> cache) {
        this.cache = cache;
    }

    @Override
    public void handleRequest(final HttpServerExchange exchange) throws Exception {
        final ResponseCache responseCache = new ResponseCache(cache, exchange);
        exchange.putAttachment(ResponseCache.ATTACHMENT_KEY, responseCache);
        exchange.addResponseWrapper(new ConduitWrapper<StreamSinkConduit>() {
            @Override
            public StreamSinkConduit wrap(final ConduitFactory<StreamSinkConduit> factory, final HttpServerExchange exchange) {
                if(!responseCache.isResponseCachable()) {
                    return factory.create();
                }
                String lengthString = exchange.getResponseHeader(CONTENT_LENGTH);
                if(lengthString == null) {
                    //we don't cache chunked requests
                    return factory.create();
                }
                int length = Integer.parseInt(lengthString);
                final CachedHttpRequest key = new CachedHttpRequest(exchange);
                final DirectBufferCache.CacheEntry entry = cache.add(key, length);

                if (entry == null || entry.buffers().length == 0 || !entry.claimEnable()) {
                    return factory.create();
                }

                if (!entry.reference()) {
                    entry.disable();
                    return factory.create();
                }

                return new ResponseCachingStreamSinkConduit(factory.create(), entry, length);
            }
        });
        HttpHandlers.executeHandler(next, exchange);
    }

    public HttpHandler getNext() {
        return next;
    }

    public CacheHandler setNext(final HttpHandler next) {
        HttpHandlers.handlerNotNull(next);
        this.next = next;
        return this;
    }
}
