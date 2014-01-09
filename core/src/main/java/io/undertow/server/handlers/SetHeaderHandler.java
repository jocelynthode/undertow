/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2012 Red Hat, Inc., and individual contributors
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

package io.undertow.server.handlers;

import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.util.HeaderPair;
import io.undertow.util.HttpString;

/**
 * @author Stuart Douglas
 */
public class SetHeaderHandler implements HttpHandler {

    private final HeaderPair header;

    private volatile HttpHandler next = ResponseCodeHandler.HANDLE_404;

    public SetHeaderHandler(final String header, final String value) {
        this.header = new HeaderPair(new HttpString(header), value);
    }

    public SetHeaderHandler(final HttpHandler next, final String header, final String value) {
        this.next = next;
        this.header = new HeaderPair(new HttpString(header), value);
    }

    @Override
    public void handleRequest(final HttpServerExchange exchange) throws Exception {
        exchange.getResponseHeaders().put(header);
        next.handleRequest(exchange);
    }
}
