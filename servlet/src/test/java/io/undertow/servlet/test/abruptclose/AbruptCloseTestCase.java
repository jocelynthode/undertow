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

package io.undertow.servlet.test.abruptclose;

import io.undertow.server.handlers.PathHandler;
import io.undertow.servlet.api.DeploymentInfo;
import io.undertow.servlet.api.DeploymentManager;
import io.undertow.servlet.api.ServletContainer;
import io.undertow.servlet.api.ServletInfo;
import io.undertow.servlet.test.util.MessageServlet;
import io.undertow.servlet.test.util.TestClassIntrospector;
import io.undertow.testutils.DefaultServer;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import javax.servlet.ServletException;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * @author Stuart Douglas
 */
@RunWith(DefaultServer.class)
public class AbruptCloseTestCase {


    public static final String HELLO_WORLD = "Hello World";

    @BeforeClass
    public static void setup() throws ServletException {

        final PathHandler root = new PathHandler();
        final ServletContainer container = ServletContainer.Factory.newInstance();

        ServletInfo s = new ServletInfo("servlet", SocketLeakServlet.class)
                .addInitParam(MessageServlet.MESSAGE, HELLO_WORLD)
                .addMapping("/a");

        DeploymentInfo builder = new DeploymentInfo()
                .setClassLoader(AbruptCloseTestCase.class.getClassLoader())
                .setContextPath("/servletContext")
                .setClassIntrospecter(TestClassIntrospector.INSTANCE)
                .setDeploymentName("servletContext.war")
                .addServlet(s);

        DeploymentManager manager = container.addDeployment(builder);
        manager.deploy();
        root.addPrefixPath(builder.getContextPath(), manager.start());

        DefaultServer.setRootHandler(root);
    }

    @Test
    public void testAbruptClose() throws IOException, InterruptedException {
        URL url = new URL(DefaultServer.getDefaultServerURL() + "/servletContext/a");

        for (int i = 0; i < 100; ++i) {
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();

            int responseCode;
            responseCode = connection.getResponseCode();
            connection.disconnect();


            System.out.println("Response received: " + responseCode);
        }
        Thread.sleep(100000000);
    }

}
