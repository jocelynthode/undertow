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

package io.undertow.test.handlers;

import java.io.IOException;

import io.undertow.io.IoCallback;
import io.undertow.io.Sender;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerConnection;
import io.undertow.server.HttpServerExchange;
import io.undertow.test.utils.DefaultServer;
import io.undertow.test.utils.HttpClientUtils;
import io.undertow.util.Headers;
import io.undertow.util.TestHttpClient;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * Tests that persistent connections work with fixed length responses
 *
 * @author Stuart Douglas
 */
@RunWith(DefaultServer.class)
public class FixedLengthResponseTestCase {

    private static final String MESSAGE = "My HTTP Request!";

    private static volatile String message;

    private static volatile HttpServerConnection connection;

    @BeforeClass
    public static void setup() {
        DefaultServer.setRootHandler(new HttpHandler() {

            @Override
            public void handleRequest(final HttpServerExchange exchange) throws Exception {
                if (connection == null) {
                    connection = exchange.getConnection();
                } else if (!DefaultServer.isAjp() && connection.getChannel() != exchange.getConnection().getChannel()) {
                    Sender sender = exchange.getResponseSender();
                    sender.send("Connection not persistent", IoCallback.END_EXCHANGE);
                    return;
                }
                exchange.setResponseHeader(Headers.CONTENT_LENGTH, message.length() + "");
                final Sender sender = exchange.getResponseSender();
                sender.send(message, IoCallback.END_EXCHANGE);
            }
        });
    }

    @Test
    public void sendHttpRequest() throws IOException {
        HttpGet get = new HttpGet(DefaultServer.getDefaultServerURL() + "/path");
        TestHttpClient client = new TestHttpClient();
        try {
            generateMessage(1);
            HttpResponse result = client.execute(get);
            Assert.assertEquals(200, result.getStatusLine().getStatusCode());
            Assert.assertEquals(message, HttpClientUtils.readResponse(result));

            generateMessage(1000);
            result = client.execute(get);
            Assert.assertEquals(200, result.getStatusLine().getStatusCode());
            Assert.assertEquals(message, HttpClientUtils.readResponse(result));
        } finally {
            client.getConnectionManager().shutdown();
        }
    }


    private static void generateMessage(int repetitions) {
        final StringBuilder builder = new StringBuilder(repetitions * MESSAGE.length());
        for (int i = 0; i < repetitions; ++i) {
            builder.append(MESSAGE);
        }
        message = builder.toString();
    }
}
