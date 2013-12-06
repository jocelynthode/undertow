package io.undertow.server.protocol.http;

import io.undertow.server.HttpServerExchange;
import io.undertow.util.HttpString;

/**
 * @author Stuart Douglas
 */
public class HttpHeaderStateMachine extends AbstractParsingStateMachine {

    @Override
    protected void handleResult(HttpString httpString, ParseState currentState, HttpServerExchange builder) {
        currentState.nextHeader = httpString;
        currentState.state++;
        currentState.parseState = 0;
    }

    @Override
    protected boolean isEnd(byte c) {
        return c == ':';
    }
}
