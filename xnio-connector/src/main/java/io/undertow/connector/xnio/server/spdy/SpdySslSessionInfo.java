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

package io.undertow.connector.xnio.server.spdy;

import io.undertow.UndertowMessages;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.RenegotiationRequiredException;
import io.undertow.server.SSLSessionInfo;
import io.undertow.connector.xnio.protocols.spdy.SpdyChannel;
import org.xnio.Options;
import org.xnio.SslClientAuthMode;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.security.cert.X509Certificate;
import java.io.IOException;
import java.security.cert.Certificate;

/**
 * @author Stuart Douglas
 */
class SpdySslSessionInfo implements SSLSessionInfo {

    private final SpdyChannel channel;

    public SpdySslSessionInfo(SpdyChannel channel) {
        this.channel = channel;
    }

    @Override
    public byte[] getSessionId() {
        return channel.getSslSession().getId();
    }

    @Override
    public String getCipherSuite() {
        return channel.getSslSession().getCipherSuite();
    }

    @Override
    public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException, RenegotiationRequiredException {
        try {
            return channel.getSslSession().getPeerCertificates();
        } catch (SSLPeerUnverifiedException e) {
            try {
                SslClientAuthMode sslClientAuthMode = channel.getOption(Options.SSL_CLIENT_AUTH_MODE);
                if (sslClientAuthMode == SslClientAuthMode.NOT_REQUESTED) {
                    throw new RenegotiationRequiredException();
                }
            } catch (IOException e1) {
                //ignore, will not actually happen
            }
            throw e;
        }
    }

    @Override
    public X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException, RenegotiationRequiredException {
        try {
            return channel.getSslSession().getPeerCertificateChain();
        } catch (SSLPeerUnverifiedException e) {
            try {
                SslClientAuthMode sslClientAuthMode = channel.getOption(Options.SSL_CLIENT_AUTH_MODE);
                if (sslClientAuthMode == SslClientAuthMode.NOT_REQUESTED) {
                    throw new RenegotiationRequiredException();
                }
            } catch (IOException e1) {
                //ignore, will not actually happen
            }
            throw e;
        }
    }
    @Override
    public void renegotiate(HttpServerExchange exchange, SslClientAuthMode sslClientAuthMode) throws IOException {
        throw UndertowMessages.MESSAGES.renegotiationNotSupported();
    }
}
