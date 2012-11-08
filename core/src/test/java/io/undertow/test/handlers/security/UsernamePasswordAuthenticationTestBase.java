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
package io.undertow.test.handlers.security;

import static org.junit.Assert.assertEquals;
import io.undertow.server.HttpCompletionHandler;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.security.AuthenticationCallHandler;
import io.undertow.server.handlers.security.AuthenticationConstraintHandler;
import io.undertow.server.handlers.security.AuthenticationHandler;
import io.undertow.server.handlers.security.AuthenticationMechanism;
import io.undertow.server.handlers.security.AuthenticationMechanismsHandler;
import io.undertow.server.handlers.security.SecurityInitialHandler;
import io.undertow.test.utils.DefaultServer;
import io.undertow.util.HeaderMap;
import io.undertow.util.HttpString;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import org.junit.Test;

/**
 * Base class for the username / password based tests.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public abstract class UsernamePasswordAuthenticationTestBase {

    protected static final AuthenticationHandler callbackHandler;

    static {
        final Map<String, char[]> users = new HashMap<String, char[]>(2);
        users.put("userOne", "passwordOne".toCharArray());
        users.put("userTwo", "passwordTwo".toCharArray());
        callbackHandler = new AuthenticationHandler() {

            @Override
            public boolean authenticate(Collection<Callback> callbacks) throws UnsupportedCallbackException {
                NameCallback ncb = null;
                PasswordCallback pcb = null;
                for (Callback current : callbacks) {
                    if (current instanceof NameCallback) {
                        ncb = (NameCallback) current;
                    } else if (current instanceof PasswordCallback) {
                        pcb = (PasswordCallback) current;
                    } else {
                        throw new UnsupportedCallbackException(current);
                    }
                }

                char[] password = users.get(ncb.getName());
                if (password == null) {
                    return false;
                }
                return pcb.getPassword().equals(password);

            }

            @Override
            public Collection<Class<? extends Callback>> getSupportedCallbacks() {
                return Arrays.<Class<? extends Callback>>asList(new Class[]{NameCallback.class, PasswordCallback.class});
            }

            @Override
            public Collection<Callback> createCallbacks() {
                return Arrays.asList(new Callback[] {new NameCallback("Name"), new PasswordCallback("Password", false)});
            }
        };
    }

    protected void setAuthenticationChain() {
        HttpHandler responseHandler = new ResponseHandler();
        HttpHandler callHandler = new AuthenticationCallHandler(responseHandler);
        HttpHandler constraintHandler = new AuthenticationConstraintHandler(callHandler);

        AuthenticationMechanism authMech = getTestMechanism();

        HttpHandler methodsAddHandler = new AuthenticationMechanismsHandler(constraintHandler,
                Collections.<AuthenticationMechanism> singletonList(authMech));
        HttpHandler initialHandler = new SecurityInitialHandler(methodsAddHandler);
        DefaultServer.setRootHandler(initialHandler);
    }

    protected abstract AuthenticationMechanism getTestMechanism();

    /**
     * Basic test to prove detection of the ResponseHandler response.
     */
    @Test
    public void testNoMechanisms() throws Exception {
        DefaultServer.setRootHandler(new ResponseHandler());

        DefaultHttpClient client = new DefaultHttpClient();
        HttpGet get = new HttpGet(DefaultServer.getDefaultServerAddress());
        HttpResponse result = client.execute(get);
        assertEquals(200, result.getStatusLine().getStatusCode());

        Header[] values = result.getHeaders("ProcessedBy");
        assertEquals(1, values.length);
        assertEquals("ResponseHandler", values[0].getValue());
    }

    /**
     * A simple end of chain handler to set a header and cause the call to return.
     *
     * Reaching this handler is a sign the mechanism handlers have allowed the request through.
     */
    protected static class ResponseHandler implements HttpHandler {

        static final HttpString PROCESSED_BY = new HttpString("ProcessedBy");

        @Override
        public void handleRequest(HttpServerExchange exchange, HttpCompletionHandler completionHandler) {
            HeaderMap responseHeader = exchange.getResponseHeaders();
            responseHeader.add(PROCESSED_BY, "ResponseHandler");

            completionHandler.handleComplete();
        }

    }

}
