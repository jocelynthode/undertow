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

package io.undertow.server.protocol.http2;

import java.nio.ByteBuffer;

import org.xnio.StreamConnection;

import io.undertow.protocols.http2.Http2Channel;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.HttpUpgradeListener;
import io.undertow.util.FlexBase64;

/**
 * Upgrade listener for HTTP2, this allows connections to be established using the upgrade
 * mechanism as detailed in Section 3.2. This should always be the first handler in a handler
 * chain.
 *
 *
 * @author Stuart Douglas
 */
public class Http2UpgradeHandler implements HttpHandler {

    private final HttpHandler next;

    public Http2UpgradeHandler(HttpHandler next) {
        this.next = next;
    }

    @Override
    public void handleRequest(HttpServerExchange exchange) throws Exception {
        String upgrade = exchange.getRequestHeaders().getFirst(Http2Channel.CLEARTEXT_UPGRADE_STRING);
        if(upgrade != null) {
            String settings = exchange.getRequestHeaders().getFirst("HTTP2-Settings");
            if(settings != null) {
                //required by spec
                final ByteBuffer settingsFrame = FlexBase64.decode(settings);
                exchange.upgradeChannel(new HttpUpgradeListener() {
                    @Override
                    public void handleUpgrade(StreamConnection streamConnection, HttpServerExchange exchange) {
                        Http2Channel channel = new Http2Channel(streamConnection, exchange.getConnection().getBufferPool(), null, false, settingsFrame);
                        Http2ReceiveListener receiveListener = new Http2ReceiveListener(next, exchange.getConnection().getUndertowOptions(), exchange.getConnection().getBufferSize());
                        channel.getReceiveSetter().set(receiveListener);
                        receiveListener.handleInitialRequest(exchange, channel);
                    }
                });
            }
        }
        next.handleRequest(exchange);
    }
}
