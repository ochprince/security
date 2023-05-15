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
import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.collect.ImmutableList;

import com.colasoft.opensearch.action.index.IndexResponse;
import com.colasoft.opensearch.client.Client;
import com.colasoft.opensearch.cluster.service.ClusterService;
import com.colasoft.opensearch.common.bytes.BytesReference;
import com.colasoft.opensearch.common.inject.Inject;
import com.colasoft.opensearch.common.settings.Settings;
import com.colasoft.opensearch.rest.RestChannel;
import com.colasoft.opensearch.rest.RestController;
import com.colasoft.opensearch.rest.RestRequest;
import com.colasoft.opensearch.security.DefaultObjectMapper;
import com.colasoft.opensearch.security.auditlog.AuditLog;
import com.colasoft.opensearch.security.configuration.AdminDNs;
import com.colasoft.opensearch.security.configuration.ConfigurationRepository;
import com.colasoft.opensearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import com.colasoft.opensearch.security.dlic.rest.validation.AllowlistValidator;
import com.colasoft.opensearch.security.privileges.PrivilegesEvaluator;
import com.colasoft.opensearch.security.securityconf.impl.CType;
import com.colasoft.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import com.colasoft.opensearch.security.ssl.transport.PrincipalExtractor;
import com.colasoft.opensearch.security.support.ConfigConstants;
import com.colasoft.opensearch.security.tools.SecurityAdmin;
import com.colasoft.opensearch.threadpool.ThreadPool;

/**
 * This class implements GET and PUT operations to manage dynamic AllowlistingSettings.
 * <p>
 * These APIs are only accessible to SuperAdmin since the configuration controls what APIs are accessible by normal users.
 * Eg: If allowlisting is enabled, and a specific API like "/_cat/nodes" is not allowlisted, then only the SuperAdmin can use "/_cat/nodes"
 * These APIs allow the SuperAdmin to enable/disable allowlisting, and also change the list of allowlisted APIs.
 * <p>
 * A SuperAdmin is identified by a certificate which represents a distinguished name(DN).
 * SuperAdmin DN's can be set in {@link ConfigConstants#SECURITY_AUTHCZ_ADMIN_DN}
 * SuperAdmin certificate for the default superuser is stored as a kirk.pem file in config folder of OpenSearch
 * <p>
 * Example calling the PUT API as SuperAdmin using curl (if http basic auth is on):
 * curl -v --cacert path_to_config/root-ca.pem --cert path_to_config/kirk.pem --key path_to_config/kirk-key.pem -XPUT https://localhost:9200/_plugins/_security/api/allowlist -H "Content-Type: application/json" -d’
 * {
 *      "enabled" : false,
 *      "requests" : {"/_cat/nodes": ["GET"], "/_plugins/_security/api/allowlist": ["GET"]}
 * }
 *
 * Example using the PATCH API to change the requests as SuperAdmin:
 * curl -v --cacert path_to_config/root-ca.pem --cert path_to_config/kirk.pem --key path_to_config/kirk-key.pem -XPATCH https://localhost:9200/_plugins/_security/api/allowlist -H "Content-Type: application/json" -d’
 * {
 *      "op":"replace",
 *      "path":"/config/requests",
 *      "value": {"/_cat/nodes": ["GET"], "/_plugins/_security/api/allowlist": ["GET"]}
 * }
 *
 * To update enabled, use the "add" operation instead of the "replace" operation, since boolean variables are not recognized as valid paths when they are false.
 * eg:
 * curl -v --cacert path_to_config/root-ca.pem --cert path_to_config/kirk.pem --key path_to_config/kirk-key.pem -XPATCH https://localhost:9200/_plugins/_security/api/allowlist -H "Content-Type: application/json" -d’
 * {
 *      "op":"add",
 *      "path":"/config/enabled",
 *      "value": true
 * }
 *
 * The backing data is stored in {@link ConfigConstants#SECURITY_CONFIG_INDEX_NAME} which is populated during bootstrap.
 * For existing clusters, {@link SecurityAdmin} tool can
 * be used to populate the index.
 * <p>
 */
public class AllowlistApiAction extends PatchableResourceApiAction {
    private static final List<Route> routes = ImmutableList.of(
            new Route(RestRequest.Method.GET, "/_plugins/_security/api/allowlist"),
            new Route(RestRequest.Method.PUT, "/_plugins/_security/api/allowlist"),
            new Route(RestRequest.Method.PATCH, "/_plugins/_security/api/allowlist")
    );

    private static final String name = "config";

    @Inject
    public AllowlistApiAction(final Settings settings, final Path configPath, final RestController controller, final Client client,
                              final AdminDNs adminDNs, final ConfigurationRepository cl, final ClusterService cs,
                              final PrincipalExtractor principalExtractor, final PrivilegesEvaluator evaluator, ThreadPool threadPool, AuditLog auditLog) {
        super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool, auditLog);
    }

    @Override
    protected void handleApiRequest(final RestChannel channel, final RestRequest request, final Client client) throws IOException {
        if (!isSuperAdmin()) {
            forbidden(channel, "API allowed only for super admin.");
            return;
        }
        super.handleApiRequest(channel, request, client);
    }

    @Override
    protected void handleGet(final RestChannel channel, RestRequest request, Client client, final JsonNode content)
            throws IOException {


        final SecurityDynamicConfiguration<?> configuration = load(getConfigName(), true);
        filter(configuration);
        successResponse(channel, configuration);
    }

    @Override
    protected void handleDelete(final RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException {
        notImplemented(channel, RestRequest.Method.DELETE);
    }

    @Override
    protected void handlePut(final RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException {
        final SecurityDynamicConfiguration<?> existingConfiguration = load(getConfigName(), false);

        if (existingConfiguration.getSeqNo() < 0) {
            forbidden(channel, "Security index need to be updated to support '" + getConfigName().toLCString() + "'. Use SecurityAdmin to populate.");
            return;
        }

        boolean existed = existingConfiguration.exists(name);
        existingConfiguration.putCObject(name, DefaultObjectMapper.readTree(content, existingConfiguration.getImplementingClass()));

        saveAndUpdateConfigs(this.securityIndexName,client, getConfigName(), existingConfiguration, new OnSucessActionListener<IndexResponse>(channel) {

            @Override
            public void onResponse(IndexResponse response) {
                if (existed) {
                    successResponse(channel, "'" + name + "' updated.");
                } else {
                    createdResponse(channel, "'" + name + "' created.");
                }
            }
        });
    }


    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    protected Endpoint getEndpoint() {
        return Endpoint.ALLOWLIST;
    }

    @Override
    protected AbstractConfigurationValidator getValidator(RestRequest request, BytesReference ref, Object... param) {
        return new AllowlistValidator(request, ref, this.settings, param);
    }

    @Override
    protected String getResourceName() {
        return name;
    }

    @Override
    protected CType getConfigName() {
        return CType.ALLOWLIST;
    }

}
