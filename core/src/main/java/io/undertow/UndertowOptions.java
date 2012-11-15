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

package io.undertow;

import io.undertow.util.AttachmentKey;
import org.xnio.Option;
import org.xnio.OptionMap;

/**
 * @author Stuart Douglas
 */
public class UndertowOptions {

    public static final AttachmentKey<OptionMap> ATTACHMENT_KEY = AttachmentKey.create(OptionMap.class);

    /**
     * The maximum size in bytes of a http request header.
     */
    public static final Option<Integer> MAX_HEADER_SIZE = Option.simple(UndertowOptions.class, "MAX_HEADER_SIZE", Integer.class);
    /**
     * The default size we allow for the HTTP header.
     */
    public static final int DEFAULT_MAX_HEADER_SIZE = 50 * 1024;

    /**
     * The maximum size of the HTTP entity body.
     */
    public static final Option<Long> MAX_ENTITY_SIZE = Option.simple(UndertowOptions.class, "MAX_ENTITY_SIZE", Long.class);

    public static final long DEFAULT_MAX_ENTITY_SIZE = 10 * 1024 * 1024;

    /**
     * The maximum number of pipelined requests that the server will process at once. Defaults to 1
     */
    public static Option<Integer> MAX_REQUESTS_PER_CONNECTION = Option.simple(UndertowOptions.class, "MAX_REQUESTS_PER_CONNECTION", Integer.class);

    /**
     * The read timeout in milliseconds. Defaults to 10000. If this is -1 read timeout is disabled
     */
    public static Option<Integer> READ_TIMEOUT = Option.simple(UndertowOptions.class, "READ_TIMEOUT", Integer.class);

    public static final int DEFAULT_READ_TIMEOUT = 10000;

    /*
    * The write timeout in milliseconds. Defaults to 10000. If this is -1 srite timeout is disabled
    */
    public static Option<Integer> WRITE_TIMEOUT = Option.simple(UndertowOptions.class, "WRITE_TIMEOUT", Integer.class);

    public static final int DEFAULT_WRITE_TIMEOUT = 10000;

    private UndertowOptions() {

    }
}
