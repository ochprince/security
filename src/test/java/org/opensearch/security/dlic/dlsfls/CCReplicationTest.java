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

package com.colasoft.opensearch.security.dlic.dlsfls;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.function.Supplier;

import org.junit.Assert;
import org.junit.Test;

import com.colasoft.opensearch.OpenSearchSecurityException;
import com.colasoft.opensearch.action.ActionListener;
import com.colasoft.opensearch.action.ActionRequest;
import com.colasoft.opensearch.action.ActionRequestValidationException;
import com.colasoft.opensearch.action.ActionResponse;
import com.colasoft.opensearch.action.ActionType;
import com.colasoft.opensearch.action.IndicesRequest;
import com.colasoft.opensearch.action.IndicesRequest.Replaceable;
import com.colasoft.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import com.colasoft.opensearch.action.index.IndexRequest;
import com.colasoft.opensearch.action.support.ActionFilters;
import com.colasoft.opensearch.action.support.HandledTransportAction;
import com.colasoft.opensearch.action.support.IndicesOptions;
import com.colasoft.opensearch.action.support.WriteRequest.RefreshPolicy;
import com.colasoft.opensearch.action.support.master.AcknowledgedRequest;
import com.colasoft.opensearch.action.support.master.AcknowledgedResponse;
import com.colasoft.opensearch.client.Client;
import com.colasoft.opensearch.cluster.health.ClusterHealthStatus;
import com.colasoft.opensearch.cluster.metadata.IndexNameExpressionResolver;
import com.colasoft.opensearch.cluster.service.ClusterService;
import com.colasoft.opensearch.common.inject.Inject;
import com.colasoft.opensearch.common.io.stream.NamedWriteableRegistry;
import com.colasoft.opensearch.common.io.stream.StreamInput;
import com.colasoft.opensearch.common.io.stream.StreamOutput;
import com.colasoft.opensearch.common.settings.Settings;
import com.colasoft.opensearch.common.xcontent.NamedXContentRegistry;
import com.colasoft.opensearch.common.xcontent.XContentType;
import com.colasoft.opensearch.env.Environment;
import com.colasoft.opensearch.env.NodeEnvironment;
import com.colasoft.opensearch.node.Node;
import com.colasoft.opensearch.node.PluginAwareNode;
import com.colasoft.opensearch.plugins.ActionPlugin;
import com.colasoft.opensearch.plugins.Plugin;
import com.colasoft.opensearch.repositories.RepositoriesService;
import com.colasoft.opensearch.rest.RestStatus;
import com.colasoft.opensearch.script.ScriptService;
import com.colasoft.opensearch.security.OpenSearchSecurityPlugin;
import com.colasoft.opensearch.security.support.ConfigConstants;
import com.colasoft.opensearch.security.test.DynamicSecurityConfig;
import com.colasoft.opensearch.tasks.Task;
import com.colasoft.opensearch.threadpool.ThreadPool;
import com.colasoft.opensearch.transport.Netty4Plugin;
import com.colasoft.opensearch.transport.TransportService;
import com.colasoft.opensearch.watcher.ResourceWatcherService;

public class CCReplicationTest extends AbstractDlsFlsTest {
    public static class MockReplicationPlugin extends Plugin implements ActionPlugin {
        public static String injectedRoles = null;

        public MockReplicationPlugin() {
        }

        @Override
        public Collection<Object> createComponents(Client client, ClusterService clusterService, ThreadPool threadPool,
            ResourceWatcherService resourceWatcherService, ScriptService scriptService,
            NamedXContentRegistry xContentRegistry, Environment environment,
            NodeEnvironment nodeEnvironment, NamedWriteableRegistry namedWriteableRegistry,
            IndexNameExpressionResolver indexNameExpressionResolver,
            Supplier<RepositoriesService> repositoriesServiceSupplier) {
            if(injectedRoles != null)
                threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES, injectedRoles);
            return new ArrayList<>();
        }

        @Override
        public List<ActionHandler<? extends ActionRequest, ? extends ActionResponse>> getActions() {
            return Arrays.asList(new ActionHandler<>(MockReplicationAction.INSTANCE, TransportMockReplicationAction.class));
        }
    }

    public static class MockReplicationAction extends ActionType<AcknowledgedResponse> {
        public static final MockReplicationAction INSTANCE = new MockReplicationAction();
        public static final String NAME = "indices:admin/plugins/replication/file_chunk";
        private MockReplicationAction() {
            super(NAME, AcknowledgedResponse::new);
        }
    }

    public static class MockReplicationRequest extends AcknowledgedRequest<MockReplicationRequest> implements Replaceable {
        private String index;
        public MockReplicationRequest(String index) {
            this.index = index;
        }

        public MockReplicationRequest(StreamInput inp) throws IOException {
            super(inp);
            index = inp.readString();
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            super.writeTo(out);
            out.writeString(index);
        }

        @Override
        public ActionRequestValidationException validate() {
            return null;
        }

        @Override
        public IndicesRequest indices(String... strings) {
            return this;
        }

        @Override
        public String[] indices() {
            return new String[]{index};
        }

        @Override
        public IndicesOptions indicesOptions() {
            return IndicesOptions.strictSingleIndexNoExpandForbidClosed();
        }

        @Override
        public boolean includeDataStreams() {
            return false;
        }
    }

    public static class TransportMockReplicationAction extends HandledTransportAction<MockReplicationRequest, AcknowledgedResponse> {

        @Inject
        public TransportMockReplicationAction(TransportService transportService,
            ActionFilters actionFilters) {
            super(MockReplicationAction.NAME, transportService, actionFilters, MockReplicationRequest::new);
        }

        @Override
        protected void doExecute(Task task, MockReplicationRequest request, ActionListener<AcknowledgedResponse> actionListener) {
            actionListener.onResponse(new AcknowledgedResponse(true));
        }
    }

    //Wait for the security plugin to load roles.
    private void waitOrThrow(Client client, String index) throws Exception {
        waitForInit(client);
        client.execute(MockReplicationAction.INSTANCE, new MockReplicationRequest(index)).actionGet();
    }

    void populateData(Client tc) {
        tc.index(new IndexRequest("hr-dls").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
            .source("{\"User\": \"testuser\",\"Date\":\"2021-01-18T17:27:20Z\",\"Designation\":\"HR\"}", XContentType.JSON)).actionGet();
        tc.index(new IndexRequest("hr-fls").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
            .source("{\"User\": \"adminuser\",\"Date\":\"2021-01-18T17:27:20Z\",\"Designation\":\"CEO\"}", XContentType.JSON)).actionGet();
        tc.index(new IndexRequest("hr-masking").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
            .source("{\"User\": \"maskeduser\",\"Date\":\"2021-01-18T17:27:20Z\",\"Designation\":\"CEO\"}", XContentType.JSON)).actionGet();
        tc.index(new IndexRequest("hr-normal").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
            .source("{\"User\": \"employee1\",\"Date\":\"2021-01-18T17:27:20Z\",\"Designation\":\"EMPLOYEE\"}", XContentType.JSON)).actionGet();
    }

    @Test
    public void testReplication() throws Exception {
        setup(Settings.EMPTY, new DynamicSecurityConfig().setSecurityRoles("roles_ccreplication.yml"), Settings.EMPTY);

        Assert.assertEquals(clusterInfo.numNodes, clusterHelper.nodeClient().admin().cluster().health(
            new ClusterHealthRequest().waitForGreenStatus()).actionGet().getNumberOfNodes());
        Assert.assertEquals(ClusterHealthStatus.GREEN, clusterHelper.nodeClient().admin().cluster().
            health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getStatus());

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

        // Set roles for the user
        MockReplicationPlugin.injectedRoles = "ccr_user|opendistro_security_human_resources_trainee";
        try (Node node = new PluginAwareNode(false, tcSettings, Netty4Plugin.class, OpenSearchSecurityPlugin.class, MockReplicationPlugin.class).start()) {
            waitOrThrow(node.client(), "hr-dls");
            Assert.fail("Expecting exception");
        } catch (OpenSearchSecurityException ex) {
            log.warn(ex.getMessage());
            Assert.assertNotNull(ex);
            Assert.assertTrue(ex.getMessage().contains("Cross Cluster Replication is not supported when FLS or DLS or Fieldmasking is activated"));
            Assert.assertEquals(ex.status(), RestStatus.FORBIDDEN);
        }

        try (Node node = new PluginAwareNode(false, tcSettings, Netty4Plugin.class, OpenSearchSecurityPlugin.class, MockReplicationPlugin.class).start()) {
            waitOrThrow(node.client(), "hr-fls");
            Assert.fail("Expecting exception");
        } catch (OpenSearchSecurityException ex) {
            log.warn(ex.getMessage());
            Assert.assertNotNull(ex);
            Assert.assertTrue(ex.getMessage().contains("Cross Cluster Replication is not supported when FLS or DLS or Fieldmasking is activated"));
            Assert.assertEquals(ex.status(), RestStatus.FORBIDDEN);
        }

        try (Node node = new PluginAwareNode(false, tcSettings, Netty4Plugin.class, OpenSearchSecurityPlugin.class, MockReplicationPlugin.class).start()) {
            waitOrThrow(node.client(), "hr-masking");
            Assert.fail("Expecting exception");
        } catch (OpenSearchSecurityException ex) {
            log.warn(ex.getMessage());
            Assert.assertNotNull(ex);
            Assert.assertTrue(ex.getMessage().contains("Cross Cluster Replication is not supported when FLS or DLS or Fieldmasking is activated"));
            Assert.assertEquals(ex.status(), RestStatus.FORBIDDEN);
        }

        try (Node node = new PluginAwareNode(false, tcSettings, Netty4Plugin.class, OpenSearchSecurityPlugin.class, MockReplicationPlugin.class).start()) {
            waitOrThrow(node.client(), "hr-normal");
            AcknowledgedResponse res = node.client().execute(MockReplicationAction.INSTANCE, new MockReplicationRequest("hr-normal")).actionGet();
            Assert.assertTrue(res.isAcknowledged());
        }
    }
}
