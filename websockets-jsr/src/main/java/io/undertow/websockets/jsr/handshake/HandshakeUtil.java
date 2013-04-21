/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2013 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.undertow.websockets.jsr.handshake;

import java.util.Arrays;
import java.util.Map;

import javax.websocket.server.ServerEndpointConfig;

import io.undertow.server.HttpServerExchange;
import io.undertow.util.AttachmentKey;
import io.undertow.util.Headers;
import io.undertow.websockets.core.WebSocketChannel;
import io.undertow.websockets.jsr.ConfiguredServerEndpoint;

/**
 * Internal util class for handshaking
 *
 * @author <a href="mailto:nmaurer@redhat.com">Norman Maurer</a>
 */
public final class HandshakeUtil {
    private static final String CONFIG_KEY = "ServerEndpointConfiguration";


    public static final AttachmentKey<Map<String, String>> PATH_PARAMS = AttachmentKey.create(Map.class);

    private HandshakeUtil() {
    }

    /**
     * Checks the orgin against the
     */
    public static boolean checkOrigin(ServerEndpointConfig config, HttpServerExchange exchange) {
        ServerEndpointConfig.Configurator c = config.getConfigurator();
        return c.checkOrigin(exchange.getRequestHeader(Headers.ORIGIN));
    }

    /**
     * Prepare for upgrade
     */
    public static void prepareUpgrade(final ServerEndpointConfig config, final HttpServerExchange exchange) {
        ExchangeHandshakeRequest request = new ExchangeHandshakeRequest(exchange);
        ExchangeHandshakeResponse response = new ExchangeHandshakeResponse(exchange);
        ServerEndpointConfig.Configurator c = config.getConfigurator();
        c.modifyHandshake(config, request, response);
        response.update();
    }

    /**
     * Set the {@link ServerEndpointConfiguration} which is used to create the {@link WebSocketChannel}.
     */
    public static void setConfig(WebSocketChannel channel, ConfiguredServerEndpoint config) {
        channel.setAttribute(CONFIG_KEY, config);
    }

    /**
     * Returns the {@link ServerEndpointConfiguration} which was used while create the {@link WebSocketChannel}.
     */
    public static ConfiguredServerEndpoint getConfig(WebSocketChannel channel) {
        return (ConfiguredServerEndpoint) channel.getAttribute(CONFIG_KEY);
    }


    static String selectSubProtocol(final ConfiguredServerEndpoint config, final String[] requestedSubprotocolArray) {
        if (config.getEndpointConfiguration().getConfigurator() != null) {
            return config.getEndpointConfiguration().getConfigurator().getNegotiatedSubprotocol(config.getEndpointConfiguration().getSubprotocols(), Arrays.asList(requestedSubprotocolArray));
        } else {
            for (final String protocol : config.getEndpointConfiguration().getSubprotocols()) {
                for (String clientsupported : requestedSubprotocolArray) {
                    if (protocol.equals(clientsupported)) {
                        return protocol;
                    }
                }
            }
            return null;
        }
    }
}
