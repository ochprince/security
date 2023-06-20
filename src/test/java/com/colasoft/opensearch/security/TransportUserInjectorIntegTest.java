/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The ColaSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package com.colasoft.opensearch.security;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.function.Supplier;

import org.junit.Assert;
import org.junit.Test;

import com.colasoft.opensearch.OpenSearchSecurityException;
import com.colasoft.opensearch.action.admin.indices.create.CreateIndexRequest;
import com.colasoft.opensearch.action.admin.indices.create.CreateIndexResponse;
import com.colasoft.opensearch.client.Client;
import com.colasoft.opensearch.cluster.metadata.IndexNameExpressionResolver;
import com.colasoft.opensearch.cluster.service.ClusterService;
import com.colasoft.opensearch.common.io.stream.NamedWriteableRegistry;
import com.colasoft.opensearch.common.settings.Settings;
import com.colasoft.opensearch.core.xcontent.NamedXContentRegistry;
import com.colasoft.opensearch.env.Environment;
import com.colasoft.opensearch.env.NodeEnvironment;
import com.colasoft.opensearch.node.Node;
import com.colasoft.opensearch.node.PluginAwareNode;
import com.colasoft.opensearch.plugins.ActionPlugin;
import com.colasoft.opensearch.plugins.Plugin;
import com.colasoft.opensearch.repositories.RepositoriesService;
import com.colasoft.opensearch.script.ScriptService;
import com.colasoft.opensearch.security.support.ConfigConstants;
import com.colasoft.opensearch.security.test.AbstractSecurityUnitTest;
import com.colasoft.opensearch.security.test.DynamicSecurityConfig;
import com.colasoft.opensearch.security.test.SingleClusterTest;
import com.colasoft.opensearch.threadpool.ThreadPool;
import com.colasoft.opensearch.transport.Netty4Plugin;
import com.colasoft.opensearch.watcher.ResourceWatcherService;

public class TransportUserInjectorIntegTest extends SingleClusterTest {

    public static class UserInjectorPlugin extends Plugin implements ActionPlugin {
        Settings settings;
        public static String injectedUser = null;

        public UserInjectorPlugin(final Settings settings, final Path configPath) {
            this.settings = settings;
        }

        @Override
        public Collection<Object> createComponents(Client client, ClusterService clusterService, ThreadPool threadPool,
                                                   ResourceWatcherService resourceWatcherService, ScriptService scriptService,
                                                   NamedXContentRegistry xContentRegistry, Environment environment,
                                                   NodeEnvironment nodeEnvironment, NamedWriteableRegistry namedWriteableRegistry,
                                                   IndexNameExpressionResolver indexNameExpressionResolver,
                                                   Supplier<RepositoriesService> repositoriesServiceSupplier) {
            if(injectedUser != null)
                threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, injectedUser);
            return new ArrayList<>();
        }
    }

    @Test
    public void testSecurityUserInjection() throws Exception {
        final Settings clusterNodeSettings = Settings.builder()
                .put(ConfigConstants.SECURITY_UNSUPPORTED_INJECT_USER_ENABLED, true)
                .build();
        setup(clusterNodeSettings, new DynamicSecurityConfig().setSecurityRolesMapping("roles_transport_inject_user.yml"), Settings.EMPTY);
        final Settings tcSettings = AbstractSecurityUnitTest.nodeRolesSettings(Settings.builder(), false, false) 
                .put(minimumSecuritySettings(Settings.EMPTY).get(0))
                .put("cluster.name", clusterInfo.clustername)
                .put("path.data", "./target/data/" + clusterInfo.clustername + "/cert/data")
                .put("path.logs", "./target/data/" + clusterInfo.clustername + "/cert/logs")
                .put("path.home", "./target")
                .put("node.name", "testclient")
                .put("discovery.initial_state_timeout", "8s")
                .put("plugins.security.allow_default_init_securityindex", "true")
                .put(ConfigConstants.SECURITY_UNSUPPORTED_INJECT_USER_ENABLED, true)
                .putList("discovery.zen.ping.unicast.hosts", clusterInfo.nodeHost + ":" + clusterInfo.nodePort)
                .build();


        // 1. without user injection
        try (Node node = new PluginAwareNode(false, tcSettings, Netty4Plugin.class,
                OpenSearchSecurityPlugin.class, UserInjectorPlugin.class).start()) {
            waitForInit(node.client());
            CreateIndexResponse cir = node.client().admin().indices().create(new CreateIndexRequest("captain-logs-1")).actionGet();
            Assert.assertTrue(cir.isAcknowledged());
        }


        // 2. with invalid backend roles
        UserInjectorPlugin.injectedUser = "ttt|kkk";
        Exception exception = null;
        try (Node node = new PluginAwareNode(false, tcSettings, Netty4Plugin.class,
                OpenSearchSecurityPlugin.class, UserInjectorPlugin.class).start()) {
            waitForInit(node.client());
            CreateIndexResponse cir = node.client().admin().indices().create(new CreateIndexRequest("captain-logs-2")).actionGet();
            Assert.fail("Expecting exception");
        } catch (OpenSearchSecurityException ex) {
            exception = ex;
            log.warn(ex.toString());
            Assert.assertNotNull(exception);
            Assert.assertTrue(exception.getMessage().contains("indices:admin/create"));
        }

        // 3. with valid backend roles for injected user
        UserInjectorPlugin.injectedUser = "injectedadmin|injecttest";
        try (Node node = new PluginAwareNode(false, tcSettings, Netty4Plugin.class,
                OpenSearchSecurityPlugin.class, UserInjectorPlugin.class).start()) {
            waitForInit(node.client());
            CreateIndexResponse cir = node.client().admin().indices().create(new CreateIndexRequest("captain-logs-2")).actionGet();
            Assert.assertTrue(cir.isAcknowledged());
        }
    }

    @Test
    public void testSecurityUserInjectionWithConfigDisabled() throws Exception {
        final Settings clusterNodeSettings = Settings.builder()
                .put(ConfigConstants.SECURITY_UNSUPPORTED_INJECT_USER_ENABLED, false)
                .build();
        setup(clusterNodeSettings, new DynamicSecurityConfig().setSecurityRolesMapping("roles_transport_inject_user.yml"), Settings.EMPTY);
        final Settings tcSettings = AbstractSecurityUnitTest.nodeRolesSettings(Settings.builder(), false, false) 
                .put(minimumSecuritySettings(Settings.EMPTY).get(0))
                .put("cluster.name", clusterInfo.clustername)
                .put("path.data", "./target/data/" + clusterInfo.clustername + "/cert/data")
                .put("path.logs", "./target/data/" + clusterInfo.clustername + "/cert/logs")
                .put("path.home", "./target")
                .put("node.name", "testclient")
                .put("discovery.initial_state_timeout", "8s")
                .put("plugins.security.allow_default_init_securityindex", "true")
                .put(ConfigConstants.SECURITY_UNSUPPORTED_INJECT_USER_ENABLED, false)
                .putList("discovery.zen.ping.unicast.hosts", clusterInfo.nodeHost + ":" + clusterInfo.nodePort)
                .build();

        // 1. without user injection
        try (Node node = new PluginAwareNode(false, tcSettings, Netty4Plugin.class,
                OpenSearchSecurityPlugin.class, UserInjectorPlugin.class).start()) {
            waitForInit(node.client());
            CreateIndexResponse cir = node.client().admin().indices().create(new CreateIndexRequest("captain-logs-1")).actionGet();
            Assert.assertTrue(cir.isAcknowledged());
        }
        
        // with invalid backend roles
        UserInjectorPlugin.injectedUser = "ttt|kkk";
        try (Node node = new PluginAwareNode(false, tcSettings, Netty4Plugin.class,
                OpenSearchSecurityPlugin.class, UserInjectorPlugin.class).start()) {
            waitForInit(node.client());
            CreateIndexResponse cir = node.client().admin().indices().create(new CreateIndexRequest("captain-logs-2")).actionGet();
            // Should pass as the user injection is disabled
            Assert.assertTrue(cir.isAcknowledged());
        }

    }
}
