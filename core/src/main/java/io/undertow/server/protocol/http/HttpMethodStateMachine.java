package io.undertow.server.protocol.http;

import io.undertow.server.HttpServerExchange;
import io.undertow.util.HttpString;

/**
 * @author Stuart Douglas
 */
public class HttpMethodStateMachine extends AbstractParsingStateMachine {

    public HttpMethodStateMachine() {
        super(' ', '\t');
    }

    @Override
    protected void handleResult(HttpString httpString, ParseState currentState, HttpServerExchange builder) {
        builder.setRequestMethod(httpString);
        currentState.state++;
        currentState.parseState = 0;
    }
}
