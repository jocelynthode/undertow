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

package io.undertow.connector.io;

/**
 * A channel
 *
 * @author Stuart Douglas
 */
public interface IOChannel<SELF extends IOChannel<SELF>> extends AutoCloseable {

    /**
     * Adds a listener that will be invoked when this channel is closed.
     *
     * @param closeListener the close listener
     */
    void addCloseListener(CloseListener<SELF> closeListener);

    /**
     * Forcibly closes this channel
     */
    @Override
    void close();

    /**
     *
     * @return The IOConnection for this channel
     */
    IOConnection getConnection();

    /**
     *
     * @return The IOThread for this channel
     */
    IOThread getIoThread();
}
