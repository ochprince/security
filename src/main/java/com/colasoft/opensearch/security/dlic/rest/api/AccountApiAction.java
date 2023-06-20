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

package com.colasoft.opensearch.security.dlic.rest.api;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.collect.ImmutableList;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;

import com.colasoft.opensearch.action.index.IndexResponse;
import com.colasoft.opensearch.client.Client;
import com.colasoft.opensearch.cluster.service.ClusterService;
import com.colasoft.opensearch.common.Strings;
import com.colasoft.opensearch.common.bytes.BytesReference;
import com.colasoft.opensearch.common.settings.Settings;
import com.colasoft.opensearch.common.transport.TransportAddress;
import com.colasoft.opensearch.common.util.concurrent.ThreadContext;
import com.colasoft.opensearch.core.xcontent.XContentBuilder;
import com.colasoft.opensearch.rest.BytesRestResponse;
import com.colasoft.opensearch.rest.RestChannel;
import com.colasoft.opensearch.rest.RestController;
import com.colasoft.opensearch.rest.RestRequest;
import com.colasoft.opensearch.rest.RestRequest.Method;
import com.colasoft.opensearch.rest.RestStatus;
import com.colasoft.opensearch.security.auditlog.AuditLog;
import com.colasoft.opensearch.security.configuration.AdminDNs;
import com.colasoft.opensearch.security.configuration.ConfigurationRepository;
import com.colasoft.opensearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import com.colasoft.opensearch.security.dlic.rest.validation.AccountValidator;
import com.colasoft.opensearch.security.privileges.PrivilegesEvaluator;
import com.colasoft.opensearch.security.securityconf.Hashed;
import com.colasoft.opensearch.security.securityconf.impl.CType;
import com.colasoft.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import com.colasoft.opensearch.security.ssl.transport.PrincipalExtractor;
import com.colasoft.opensearch.security.support.ConfigConstants;
import com.colasoft.opensearch.security.support.SecurityJsonNode;
import com.colasoft.opensearch.security.user.User;
import com.colasoft.opensearch.threadpool.ThreadPool;

import static com.colasoft.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;
import static com.colasoft.opensearch.security.dlic.rest.support.Utils.hash;

/**
 * Rest API action to fetch or update account details of the signed-in user.
 * Currently this action serves GET and PUT request for /_opendistro/_security/api/account endpoint
 */
public class AccountApiAction extends AbstractApiAction {
    private static final String RESOURCE_NAME = "account";
    private static final List<Route> routes = addRoutesPrefix(ImmutableList.of(
            new Route(Method.GET, "/account"),
            new Route(Method.PUT, "/account")
    ));

    private final PrivilegesEvaluator privilegesEvaluator;
    private final ThreadContext threadContext;

    public AccountApiAction(Settings settings,
                            Path configPath,
                            RestController controller,
                            Client client,
                            AdminDNs adminDNs,
                            ConfigurationRepository cl,
                            ClusterService cs,
                            PrincipalExtractor principalExtractor,
                            PrivilegesEvaluator privilegesEvaluator,
                            ThreadPool threadPool,
                            AuditLog auditLog) {
        super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, privilegesEvaluator, threadPool, auditLog);
        this.privilegesEvaluator = privilegesEvaluator;
        this.threadContext = threadPool.getThreadContext();
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    /**
     * GET request to fetch account details
     *
     * Sample request:
     * GET _opendistro/_security/api/account
     *
     * Sample response:
     * {
     *   "user_name" : "test",
     *   "is_reserved" : false,
     *   "is_hidden" : false,
     *   "is_internal_user" : true,
     *   "user_requested_tenant" : "__user__",
     *   "backend_roles" : [ ],
     *   "custom_attribute_names" : [ ],
     *   "tenants" : {
     *     "test" : true
     *   },
     *   "roles" : [
     *     "own_index"
     *   ]
     * }
     *
     * @param channel channel to return response
     * @param request request to be served
     * @param client client
     * @param content content body
     * @throws IOException
     */
    @Override
    protected void handleGet(RestChannel channel, RestRequest request, Client client, final JsonNode content) throws IOException {
        final XContentBuilder builder = channel.newBuilder();
        BytesRestResponse response;

        try {
            builder.startObject();
            final User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
            if (user != null) {
                final TransportAddress remoteAddress = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);
                final Set<String> securityRoles = privilegesEvaluator.mapRoles(user, remoteAddress);
                final SecurityDynamicConfiguration<?> configuration = load(getConfigName(), false);

                builder.field("user_name", user.getName())
                        .field("is_reserved", isReserved(configuration, user.getName()))
                        .field("is_hidden", configuration.isHidden(user.getName()))
                        .field("is_internal_user", configuration.exists(user.getName()))
                        .field("user_requested_tenant", user.getRequestedTenant())
                        .field("backend_roles", user.getRoles())
                        .field("custom_attribute_names", user.getCustomAttributesMap().keySet())
                        .field("tenants", privilegesEvaluator.mapTenants(user, securityRoles))
                        .field("roles", securityRoles);
            }
            builder.endObject();

            response = new BytesRestResponse(RestStatus.OK, builder);
        } catch (final Exception exception) {
            log.error(exception.toString());

            builder.startObject()
                    .field("error", exception.toString())
                    .endObject();

            response = new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, builder);
        }
        channel.sendResponse(response);
    }

    /**
     * PUT request to update account password.
     *
     * Sample request:
     * PUT _opendistro/_security/api/account
     * {
     *     "current_password": "old-pass",
     *     "password": "new-pass"
     * }
     *
     * Sample response:
     * {
     *     "status":"OK",
     *     "message":"'test' updated."
     * }
     *
     * @param channel channel to return response
     * @param request request to be served
     * @param client client
     * @param content content body
     * @throws IOException
     */
    @Override
    protected void handlePut(RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException {
        final User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        final String username = user.getName();
        final SecurityDynamicConfiguration<?> internalUser = load(CType.INTERNALUSERS, false);

        if (!internalUser.exists(username)) {
            notFound(channel, "Could not find user.");
            return;
        }

        if (!isWriteable(channel, internalUser, username)) {
            return;
        }

        final SecurityJsonNode securityJsonNode = new SecurityJsonNode(content);
        final String currentPassword = content.get("current_password").asText();
        final Hashed internalUserEntry = (Hashed) internalUser.getCEntry(username);
        final String currentHash = internalUserEntry.getHash();

        if (currentHash == null || !OpenBSDBCrypt.checkPassword(currentHash, currentPassword.toCharArray())) {
            badRequestResponse(channel, "Could not validate your current password.");
            return;
        }

        // if password is set, it takes precedence over hash
        final String password = securityJsonNode.get("password").asString();
        final String hash;
        if (Strings.isNullOrEmpty(password)) {
            hash = securityJsonNode.get("hash").asString();
        } else {
            hash = hash(password.toCharArray());
        }
        if (Strings.isNullOrEmpty(hash)) {
            badRequestResponse(channel, "Both provided password and hash cannot be null/empty.");
            return;
        }

        internalUserEntry.setHash(hash);

        AccountApiAction.saveAndUpdateConfigs(this.securityIndexName, client, CType.INTERNALUSERS, internalUser, new OnSucessActionListener<IndexResponse>(channel) {
            @Override
            public void onResponse(IndexResponse response) {
                successResponse(channel, "'" + username + "' updated.");
            }
        });
    }

    @Override
    protected AbstractConfigurationValidator getValidator(RestRequest request, BytesReference ref, Object... params) {
        final User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        return new AccountValidator(request, ref, this.settings, user.getName());
    }

    @Override
    protected String getResourceName() {
        return RESOURCE_NAME;
    }

    @Override
    protected Endpoint getEndpoint() {
        return Endpoint.ACCOUNT;
    }

    @Override
    protected void filter(SecurityDynamicConfiguration<?> builder) {
        super.filter(builder);
        // replace password hashes in addition. We must not remove them from the
        // Builder since this would remove users completely if they
        // do not have any addition properties like roles or attributes
        builder.clearHashes();
    }

    @Override
    protected CType getConfigName() {
        return CType.INTERNALUSERS;
    }
}
