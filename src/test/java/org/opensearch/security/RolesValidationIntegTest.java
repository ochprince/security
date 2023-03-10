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
import com.colasoft.opensearch.action.admin.indices.exists.indices.IndicesExistsRequest;
import com.colasoft.opensearch.action.admin.indices.exists.indices.IndicesExistsResponse;
import com.colasoft.opensearch.client.Client;
import com.colasoft.opensearch.cluster.metadata.IndexNameExpressionResolver;
import com.colasoft.opensearch.cluster.service.ClusterService;
import com.colasoft.opensearch.common.io.stream.NamedWriteableRegistry;
import com.colasoft.opensearch.common.settings.Settings;
import com.colasoft.opensearch.common.xcontent.NamedXContentRegistry;
import com.colasoft.opensearch.env.Environment;
import com.colasoft.opensearch.env.NodeEnvironment;
import com.colasoft.opensearch.node.Node;
import com.colasoft.opensearch.node.PluginAwareNode;
import com.colasoft.opensearch.plugins.ActionPlugin;
import com.colasoft.opensearch.plugins.Plugin;
import com.colasoft.opensearch.repositories.RepositoriesService;
import com.colasoft.opensearch.script.ScriptService;
import com.colasoft.opensearch.security.support.ConfigConstants;
import com.colasoft.opensearch.security.test.DynamicSecurityConfig;
import com.colasoft.opensearch.security.test.SingleClusterTest;
import com.colasoft.opensearch.threadpool.ThreadPool;
import com.colasoft.opensearch.transport.Netty4Plugin;
import com.colasoft.opensearch.watcher.ResourceWatcherService;

public class RolesValidationIntegTest extends SingleClusterTest {

    public static class RolesValidationPlugin extends Plugin implements ActionPlugin {
        Settings settings;
        public static String rolesValidation = null;

        public RolesValidationPlugin(final Settings settings, final Path configPath) {
            this.settings = settings;
        }

        @Override
        public Collection<Object> createComponents(Client client, ClusterService clusterService, ThreadPool threadPool,
                                                   ResourceWatcherService resourceWatcherService, ScriptService scriptService,
                                                   NamedXContentRegistry xContentRegistry, Environment environment,
                                                   NodeEnvironment nodeEnvironment, NamedWriteableRegistry namedWriteableRegistry,
                                                   IndexNameExpressionResolver indexNameExpressionResolver,
                                                   Supplier<RepositoriesService> repositoriesServiceSupplier) {
            if(rolesValidation != null) {
                threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES, "test|opendistro_security_all_access");
                threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES_VALIDATION, rolesValidation);
            }
            return new ArrayList<>();
        }
    }

    @Test
    public void testRolesValidation() throws Exception {
        setup(Settings.EMPTY, new DynamicSecurityConfig().setSecurityRoles("roles.yml"), Settings.EMPTY);

        final Settings tcSettings = Settings.builder()
                .put(minimumSecuritySettings(Settings.EMPTY).get(0))
                .put("cluster.name", clusterInfo.clustername)
                .put("node.data", false)
                .put("node.master", false)
                .put("node.ingest", false)
                .put("path.data", "./target/data/" + clusterInfo.clustername + "/cert/data")
                .put("path.logs", "./target/data/" + clusterInfo.clustername + "/cert/logs")
                .put("path.home", "./target")
                .put("node.name", "testclient")
                .put("discovery.initial_state_timeout", "8s")
                .put("plugins.security.allow_default_init_securityindex", "true")
                .putList("discovery.zen.ping.unicast.hosts", clusterInfo.nodeHost + ":" + clusterInfo.nodePort)
                .build();

        // 1. Without roles validation
        try (Node node = new PluginAwareNode(false, tcSettings, Netty4Plugin.class,
                OpenSearchSecurityPlugin.class, RolesValidationPlugin.class).start()) {
            waitForInit(node.client());
            CreateIndexResponse cir = node.client().admin().indices().create(new CreateIndexRequest("captain-logs-1")).actionGet();
            Assert.assertTrue(cir.isAcknowledged());
            IndicesExistsResponse ier = node.client().admin().indices().exists(new IndicesExistsRequest("captain-logs-1")).actionGet();
            Assert.assertTrue(ier.isExists());
        }

        OpenSearchSecurityException exception = null;
        // 2. with roles invalid to the user
        RolesValidationPlugin.rolesValidation = "invalid_role";
        try (Node node = new PluginAwareNode(false, tcSettings, Netty4Plugin.class,
                OpenSearchSecurityPlugin.class, RolesValidationPlugin.class).start()) {
            waitForInit(node.client());
            CreateIndexResponse cir = node.client().admin().indices().create(new CreateIndexRequest("captain-logs-2")).actionGet();
        } catch (OpenSearchSecurityException ex) {
            exception = ex;
        }
        Assert.assertNotNull(exception);
        Assert.assertTrue(exception.getMessage().contains("No mapping for"));

        // 3. with roles valid to the user
        RolesValidationPlugin.rolesValidation = "opendistro_security_all_access";
        try (Node node = new PluginAwareNode(false, tcSettings, Netty4Plugin.class,
                OpenSearchSecurityPlugin.class, RolesValidationPlugin.class).start()) {
            waitForInit(node.client());
            CreateIndexResponse cir = node.client().admin().indices().create(new CreateIndexRequest("captain-logs-3")).actionGet();
            Assert.assertTrue(cir.isAcknowledged());
        }
    }
}
