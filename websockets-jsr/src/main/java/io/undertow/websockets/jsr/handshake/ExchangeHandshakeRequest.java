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

import java.net.URI;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.websocket.server.HandshakeRequest;

import io.undertow.server.HttpServerExchange;
import io.undertow.util.HttpString;

/**
 * {@link HandshakeRequest} which wraps a {@link io.undertow.websockets.spi.WebSocketHttpExchange} to act on it.
 * Once the processing of it is done {@link #update()} must be called to persist any changes
 * made.
 *
 * @author <a href="mailto:nmaurer@redhat.com">Norman Maurer</a>
 */
public final class ExchangeHandshakeRequest implements HandshakeRequest {
    private final HttpServerExchange exchange;
    private Map<String, List<String>> headers;

    public ExchangeHandshakeRequest(final HttpServerExchange exchange) {
        this.exchange = exchange;
    }

    @Override
    public Map<String, List<String>> getHeaders() {
        if (headers == null) {
            headers = new HashMap<>();
            for(HttpString name : exchange.getRequestHeaderNames()) {
                headers.put(name.toString(), new ArrayList<String>(exchange.getRequestHeaders(name)));
            }
        }
        return headers;
    }

    @Override
    public Principal getUserPrincipal() {
        return null; //TODO
    }

    @Override
    public URI getRequestURI() {
        return URI.create(exchange.getRequestURI());
    }

    @Override
    public boolean isUserInRole(String role) {
        return false;
    }

    @Override
    public Object getHttpSession() {
        return null; // TODO exchange.getSession();
    }

    @Override
    public Map<String, List<String>> getParameterMap() {
        return Collections.emptyMap();
    }

    @Override
    public String getQueryString() {
        return exchange.getQueryString();
    }
}
