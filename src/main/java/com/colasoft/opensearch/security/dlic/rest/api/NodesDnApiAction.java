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

package com.colasoft.opensearch.security.dlic.rest.api;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.collect.ImmutableList;

import com.colasoft.opensearch.client.Client;
import com.colasoft.opensearch.cluster.service.ClusterService;
import com.colasoft.opensearch.common.bytes.BytesReference;
import com.colasoft.opensearch.common.inject.Inject;
import com.colasoft.opensearch.common.settings.Settings;
import com.colasoft.opensearch.rest.RestChannel;
import com.colasoft.opensearch.rest.RestController;
import com.colasoft.opensearch.rest.RestRequest;
import com.colasoft.opensearch.rest.RestRequest.Method;
import com.colasoft.opensearch.security.auditlog.AuditLog;
import com.colasoft.opensearch.security.configuration.AdminDNs;
import com.colasoft.opensearch.security.configuration.ConfigurationRepository;
import com.colasoft.opensearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import com.colasoft.opensearch.security.dlic.rest.validation.NodesDnValidator;
import com.colasoft.opensearch.security.privileges.PrivilegesEvaluator;
import com.colasoft.opensearch.security.securityconf.impl.CType;
import com.colasoft.opensearch.security.securityconf.impl.NodesDn;
import com.colasoft.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import com.colasoft.opensearch.security.ssl.transport.PrincipalExtractor;
import com.colasoft.opensearch.security.support.ConfigConstants;
import com.colasoft.opensearch.threadpool.ThreadPool;

import static com.colasoft.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

/**
 * This class implements CRUD operations to manage dynamic NodesDn. The primary usecase is targeted at cross-cluster where
 * in node restart can be avoided by populating the coordinating cluster's nodes_dn values.
 *
 * The APIs are only accessible to SuperAdmin since the configuration controls the core application layer trust validation.
 * By default the APIs are disabled and can be enabled by a YML setting - {@link ConfigConstants#SECURITY_NODES_DN_DYNAMIC_CONFIG_ENABLED}
 *
 * The backing data is stored in {@link ConfigConstants#SECURITY_CONFIG_INDEX_NAME} which is populated during bootstrap.
 * For existing clusters, {@link SecurityAdmin} tool can
 * be used to populate the index.
 *
 * See {@link NodesDnApiTest} for usage examples.
 */
public class NodesDnApiAction extends PatchableResourceApiAction {
    public static final String STATIC_OPENSEARCH_YML_NODES_DN = "STATIC_OPENSEARCH_YML_NODES_DN";
    private final List<String> staticNodesDnFromEsYml;

    private static final List<Route> routes = addRoutesPrefix(ImmutableList.of(
            new Route(Method.GET, "/nodesdn/{name}"),
            new Route(Method.GET, "/nodesdn/"),
            new Route(Method.DELETE, "/nodesdn/{name}"),
            new Route(Method.PUT, "/nodesdn/{name}"),
            new Route(Method.PATCH, "/nodesdn/"),
            new Route(Method.PATCH, "/nodesdn/{name}")
    ));

    @Inject
    public NodesDnApiAction(final Settings settings, final Path configPath, final RestController controller, final Client client,
                            final AdminDNs adminDNs, final ConfigurationRepository cl, final ClusterService cs,
                            final PrincipalExtractor principalExtractor, final PrivilegesEvaluator evaluator, ThreadPool threadPool, AuditLog auditLog) {
        super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool, auditLog);
        this.staticNodesDnFromEsYml = settings.getAsList(ConfigConstants.SECURITY_NODES_DN, Collections.emptyList());
    }

    @Override
    public List<Route> routes() {
        if (settings.getAsBoolean(ConfigConstants.SECURITY_NODES_DN_DYNAMIC_CONFIG_ENABLED, false)) {
            return routes;
        }
        return Collections.emptyList();
    }

    @Override
    protected void handleApiRequest(RestChannel channel, RestRequest request, Client client) throws IOException {
        if (!isSuperAdmin()) {
            forbidden(channel, "API allowed only for admin.");
            return;
        }
        super.handleApiRequest(channel, request, client);
    }

    protected void consumeParameters(final RestRequest request) {
        request.param("name");
        request.param("show_all");
    }

    @Override
    protected boolean isReadOnly(SecurityDynamicConfiguration<?> existingConfiguration, String name) {
        if (STATIC_OPENSEARCH_YML_NODES_DN.equals(name)) {
            return true;
        }
        return super.isReadOnly(existingConfiguration, name);
    }

    @Override
    protected void handleGet(final RestChannel channel, RestRequest request, Client client, final JsonNode content) throws IOException {
        final String resourcename = request.param("name");

        final SecurityDynamicConfiguration<?> configuration = load(getConfigName(), true);
        filter(configuration);

        // no specific resource requested, return complete config
        if (resourcename == null || resourcename.length() == 0) {
            final Boolean showAll = request.paramAsBoolean("show_all", Boolean.FALSE);
            if (showAll) {
                putStaticEntry(configuration);
            }
            successResponse(channel, configuration);
            return;
        }

        if (!configuration.exists(resourcename)) {
            notFound(channel, "Resource '" + resourcename + "' not found.");
            return;
        }

        configuration.removeOthers(resourcename);
        successResponse(channel, configuration);
    }

    private void putStaticEntry(SecurityDynamicConfiguration<?> configuration) {
        if (NodesDn.class.equals(configuration.getImplementingClass())) {
            NodesDn nodesDn = new NodesDn();
            nodesDn.setNodesDn(staticNodesDnFromEsYml);
            ((SecurityDynamicConfiguration<NodesDn>)configuration).putCEntry(STATIC_OPENSEARCH_YML_NODES_DN, nodesDn);
        } else {
            throw new RuntimeException("Unknown class type - " + configuration.getImplementingClass());
        }
    }

    @Override
    protected Endpoint getEndpoint() {
        return Endpoint.NODESDN;
    }

    @Override
    protected String getResourceName() {
        return "nodesdn";
    }

    @Override
    protected CType getConfigName() {
        return CType.NODESDN;
    }

    @Override
    protected AbstractConfigurationValidator getValidator(RestRequest request, BytesReference ref, Object... params) {
        return new NodesDnValidator(request, ref, this.settings, params);
    }
}
