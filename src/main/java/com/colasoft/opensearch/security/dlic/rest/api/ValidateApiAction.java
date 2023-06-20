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
import java.util.Collections;
import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;

import com.colasoft.opensearch.client.Client;
import com.colasoft.opensearch.cluster.service.ClusterService;
import com.colasoft.opensearch.common.bytes.BytesReference;
import com.colasoft.opensearch.common.collect.Tuple;
import com.colasoft.opensearch.common.inject.Inject;
import com.colasoft.opensearch.common.settings.Settings;
import com.colasoft.opensearch.rest.RestChannel;
import com.colasoft.opensearch.rest.RestController;
import com.colasoft.opensearch.rest.RestRequest;
import com.colasoft.opensearch.rest.RestRequest.Method;
import com.colasoft.opensearch.security.auditlog.AuditLog;
import com.colasoft.opensearch.security.auditlog.config.AuditConfig;
import com.colasoft.opensearch.security.configuration.AdminDNs;
import com.colasoft.opensearch.security.configuration.ConfigurationRepository;
import com.colasoft.opensearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import com.colasoft.opensearch.security.dlic.rest.validation.NoOpValidator;
import com.colasoft.opensearch.security.privileges.PrivilegesEvaluator;
import com.colasoft.opensearch.security.securityconf.Migration;
import com.colasoft.opensearch.security.securityconf.impl.CType;
import com.colasoft.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import com.colasoft.opensearch.security.securityconf.impl.v6.ActionGroupsV6;
import com.colasoft.opensearch.security.securityconf.impl.v6.ConfigV6;
import com.colasoft.opensearch.security.securityconf.impl.v6.InternalUserV6;
import com.colasoft.opensearch.security.securityconf.impl.v6.RoleMappingsV6;
import com.colasoft.opensearch.security.securityconf.impl.v6.RoleV6;
import com.colasoft.opensearch.security.securityconf.impl.v7.ActionGroupsV7;
import com.colasoft.opensearch.security.securityconf.impl.v7.ConfigV7;
import com.colasoft.opensearch.security.securityconf.impl.v7.InternalUserV7;
import com.colasoft.opensearch.security.securityconf.impl.v7.RoleMappingsV7;
import com.colasoft.opensearch.security.securityconf.impl.v7.RoleV7;
import com.colasoft.opensearch.security.securityconf.impl.v7.TenantV7;
import com.colasoft.opensearch.security.ssl.transport.PrincipalExtractor;
import com.colasoft.opensearch.threadpool.ThreadPool;

import static com.colasoft.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;


public class ValidateApiAction extends AbstractApiAction {
    private static final List<Route> routes = addRoutesPrefix(Collections.singletonList(
            new Route(Method.GET, "/validate")
    ));

    @Inject
    public ValidateApiAction(final Settings settings, final Path configPath, final RestController controller, final Client client,
                             final AdminDNs adminDNs, final ConfigurationRepository cl, final ClusterService cs, final PrincipalExtractor principalExtractor,
                             final PrivilegesEvaluator evaluator, ThreadPool threadPool, AuditLog auditLog) {
        super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool, auditLog);
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    protected Endpoint getEndpoint() {
        return Endpoint.VALIDATE;
    }

    @SuppressWarnings("unchecked")
    @Override
    protected void handleGet(RestChannel channel, RestRequest request, Client client, final JsonNode content) throws IOException {

        final boolean acceptInvalid = request.paramAsBoolean("accept_invalid", false);

        final SecurityDynamicConfiguration<?> loadedConfig = load(CType.CONFIG, true, acceptInvalid);

        if (loadedConfig.getVersion() != 1) {
            badRequestResponse(channel, "Can not migrate configuration because it was already migrated.");
            return;
        }

        try {
            final SecurityDynamicConfiguration<ConfigV6> configV6 = (SecurityDynamicConfiguration<ConfigV6>) loadedConfig;
            final SecurityDynamicConfiguration<ActionGroupsV6> actionGroupsV6 = (SecurityDynamicConfiguration<ActionGroupsV6>) load(CType.ACTIONGROUPS, true, acceptInvalid);
            final SecurityDynamicConfiguration<InternalUserV6> internalUsersV6 = (SecurityDynamicConfiguration<InternalUserV6>) load(CType.INTERNALUSERS, true, acceptInvalid);
            final SecurityDynamicConfiguration<RoleV6> rolesV6 = (SecurityDynamicConfiguration<RoleV6>) load(CType.ROLES, true, acceptInvalid);
            final SecurityDynamicConfiguration<RoleMappingsV6> rolesmappingV6 = (SecurityDynamicConfiguration<RoleMappingsV6>) load(CType.ROLESMAPPING, true, acceptInvalid);
            final SecurityDynamicConfiguration<AuditConfig> auditConfigV6 = (SecurityDynamicConfiguration<AuditConfig>) load(CType.AUDIT, true);

            final SecurityDynamicConfiguration<ActionGroupsV7> actionGroupsV7 = Migration.migrateActionGroups(actionGroupsV6);
            final SecurityDynamicConfiguration<ConfigV7> configV7 = Migration.migrateConfig(configV6);
            final SecurityDynamicConfiguration<InternalUserV7> internalUsersV7 = Migration.migrateInternalUsers(internalUsersV6);
            final Tuple<SecurityDynamicConfiguration<RoleV7>, SecurityDynamicConfiguration<TenantV7>> rolesTenantsV7 = Migration.migrateRoles(rolesV6,
                rolesmappingV6);
            final SecurityDynamicConfiguration<RoleMappingsV7> rolesmappingV7 = Migration.migrateRoleMappings(rolesmappingV6);
            final SecurityDynamicConfiguration<AuditConfig> auditConfigV7 = Migration.migrateAudit(auditConfigV6);

            successResponse(channel, "OK.");
        } catch (Exception e) {
            internalErrorResponse(channel, "Configuration is not valid.");
        }
    }

    @Override
    protected void handleDelete(RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException {
        notImplemented(channel, Method.POST);
    }

    @Override
    protected void handlePost(RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException {
        notImplemented(channel, Method.GET);
    }

    @Override
    protected void handlePut(RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException {
        notImplemented(channel, Method.PUT);
    }

    @Override
    protected AbstractConfigurationValidator getValidator(RestRequest request, BytesReference ref, Object... param) {
        return new NoOpValidator(request, ref, this.settings, param);
    }

    @Override
    protected String getResourceName() {
        // not needed
        return null;
    }

    @Override
    protected CType getConfigName() {
        return null;
    }

    @Override
    protected void consumeParameters(final RestRequest request) {
        request.paramAsBoolean("accept_invalid", false);
    }

}
