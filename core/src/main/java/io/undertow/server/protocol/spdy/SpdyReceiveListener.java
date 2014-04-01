package io.undertow.server.protocol.spdy;

import io.undertow.UndertowLogger;
import io.undertow.UndertowOptions;
import io.undertow.server.Connectors;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.spdy.SpdyChannel;
import io.undertow.spdy.SpdyPingStreamSourceChannel;
import io.undertow.spdy.SpdyStreamSourceChannel;
import io.undertow.spdy.SpdySynStreamStreamSourceChannel;
import io.undertow.util.Headers;
import io.undertow.util.HttpString;
import io.undertow.util.URLUtils;
import org.xnio.ChannelListener;
import org.xnio.IoUtils;
import org.xnio.OptionMap;

import javax.net.ssl.SSLSession;
import java.io.IOException;

/**
 * The recieve listener for a SPDY connection.
 * <p/>
 * A new instance is created per connection.
 *
 * @author Stuart Douglas
 */
public class SpdyReceiveListener implements ChannelListener<SpdyChannel> {

    private static final HttpString METHOD = new HttpString(":method");
    private static final HttpString PATH = new HttpString(":path");
    private static final HttpString SCHEME = new HttpString(":scheme");
    private static final HttpString VERSION = new HttpString(":version");
    private static final HttpString HOST = new HttpString(":host");

    private final HttpHandler rootHandler;
    private final long maxEntitySize;
    private final OptionMap undertowOptions;
    private final String encoding;
    private final StringBuilder decodeBuffer = new StringBuilder();
    private final boolean allowEncodingSlash;
    private final int bufferSize;


    public SpdyReceiveListener(HttpHandler rootHandler, OptionMap undertowOptions, int bufferSize) {
        this.rootHandler = rootHandler;
        this.undertowOptions = undertowOptions;
        this.bufferSize = bufferSize;
        this.maxEntitySize = undertowOptions.get(UndertowOptions.MAX_ENTITY_SIZE, UndertowOptions.DEFAULT_MAX_ENTITY_SIZE);
        this.allowEncodingSlash = undertowOptions.get(UndertowOptions.ALLOW_ENCODED_SLASH, false);
        if (undertowOptions.get(UndertowOptions.DECODE_URL, true)) {
            this.encoding = undertowOptions.get(UndertowOptions.URL_CHARSET, "UTF-8");
        } else {
            this.encoding = null;
        }
    }

    @Override
    public void handleEvent(SpdyChannel channel) {

        try {
            final SpdyStreamSourceChannel frame = channel.receive();
            if (frame == null) {
                return;
            }
            if (frame instanceof SpdyPingStreamSourceChannel) {
                handlePing((SpdyPingStreamSourceChannel) frame);
            } else if (frame instanceof SpdySynStreamStreamSourceChannel) {
                //we have a request
                final SpdySynStreamStreamSourceChannel dataChannel = (SpdySynStreamStreamSourceChannel) frame;
                final SpdyServerConnection connection = new SpdyServerConnection(channel, dataChannel, undertowOptions, bufferSize);

                final HttpServerExchange exchange = new HttpServerExchange(connection, dataChannel.getHeaders(), dataChannel.getResponseChannel().getHeaders(), maxEntitySize);
                exchange.setRequestScheme(exchange.getRequestHeaders().getFirst(SCHEME));
                exchange.setProtocol(new HttpString(exchange.getRequestHeaders().getFirst(VERSION)));
                exchange.setRequestMethod(new HttpString(exchange.getRequestHeaders().getFirst(METHOD)));
                exchange.getRequestHeaders().add(Headers.HOST, exchange.getRequestHeaders().getFirst(HOST));
                final String path = exchange.getRequestHeaders().getFirst(PATH);
                setRequestPath(exchange, path, encoding, allowEncodingSlash, decodeBuffer);

                SSLSession session = channel.getSslSession();
                if(session != null) {
                    connection.setSslSessionInfo(new SpdySslSessionInfo(channel));
                }

                Connectors.executeRootHandler(rootHandler, exchange);
            }

        } catch (IOException e) {
            e.printStackTrace();
            UndertowLogger.REQUEST_IO_LOGGER.ioException(e);
            IoUtils.safeClose(channel);
        }
    }

    private void handlePing(SpdyPingStreamSourceChannel frame) {
        int id = frame.getId();
        if (id % 2 == 1) {
            //client side ping, return it
            frame.getSpdyChannel().sendPing(id);
        }
    }


    /**
     * Sets the request path and query parameters, decoding to the requested charset.
     *
     * @param exchange    The exchange
     * @param encodedPath The encoded path
     * @param charset     The charset
     */
    private static void setRequestPath(final HttpServerExchange exchange, final String encodedPath, final String charset, final boolean allowEncodedSlash, StringBuilder decodeBuffer) {
        if (charset == null) {
            setRequestPath(exchange, encodedPath);
        } else {
            boolean requiresDecode = false;
            for (int i = 0; i < encodedPath.length(); ++i) {
                char c = encodedPath.charAt(i);
                if (c == '?') {
                    String part;
                    if (requiresDecode) {
                        part = URLUtils.decode(encodedPath.substring(0, i), charset, allowEncodedSlash, decodeBuffer);
                    } else {
                        part = encodedPath.substring(0, i);
                    }
                    exchange.setRequestPath(part);
                    exchange.setRelativePath(part);
                    exchange.setRequestURI(part);
                    handleQueryParameter(exchange, encodedPath, null, i + 1, decodeBuffer);
                    return;
                } else if (c == '%') {
                    requiresDecode = true;
                }
            }
            String part;
            if (requiresDecode) {
                part = URLUtils.decode(encodedPath, charset, allowEncodedSlash, decodeBuffer);
            } else {
                part = encodedPath;
            }
            exchange.setRequestPath(part);
            exchange.setRelativePath(part);
            exchange.setRequestURI(part);
        }
    }

    private static void setRequestPath(final HttpServerExchange exchange, final String path) {
        for (int i = 0; i < path.length(); ++i) {
            if (path.charAt(i) == '?') {
                String part = path.substring(0, i);
                exchange.setRequestPath(part);
                exchange.setRelativePath(part);
                exchange.setRequestURI(part);
                handleQueryParameter(exchange, path, null, i + 1, null);
                return;
            }
        }
        exchange.setRequestPath(path);
        exchange.setRelativePath(path);
        exchange.setRequestURI(path);
    }

    private static void handleQueryParameter(HttpServerExchange exchange, String path, String charset, int start, StringBuilder decodeBuffer) {
        //TODO: path params
        exchange.setQueryString(path.substring(start));
        String headerName = null;
        int currentPos = start;
        boolean decodeRequired = false;
        for (int i = start; i < path.length(); ++i) {
            char c = path.charAt(i);
            if (c == '=' && headerName == null) {
                headerName = path.substring(currentPos, i);
                if (charset != null && decodeRequired) {
                    headerName = URLUtils.decode(headerName, charset, true, decodeBuffer);
                }

                currentPos = i;
                decodeRequired = false;
            } else if (c == '&' && headerName != null) {
                String value = path.substring(currentPos, i);
                if (charset != null && decodeRequired) {
                    value = URLUtils.decode(value, charset, true, decodeBuffer);
                }
                exchange.addQueryParam(headerName, value);
                headerName = null;
                currentPos = i;
                decodeRequired = false;
            } else if (c == '%') {
                decodeRequired = true;
            }
        }
        if (headerName != null) {
            String value = path.substring(currentPos);
            if (charset != null && decodeRequired) {
                value = URLUtils.decode(value, charset, true, decodeBuffer);
            }
            exchange.addQueryParam(headerName, value);
        } else if (currentPos != path.length()) {
            headerName = path.substring(currentPos);
            if (charset != null && decodeRequired) {
                headerName = URLUtils.decode(headerName, charset, true, decodeBuffer);
            }
            exchange.addQueryParam(headerName, "");
        }
    }
}
