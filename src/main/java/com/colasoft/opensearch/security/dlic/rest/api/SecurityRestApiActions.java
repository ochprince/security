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

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import com.colasoft.opensearch.client.Client;
import com.colasoft.opensearch.cluster.service.ClusterService;
import com.colasoft.opensearch.common.settings.Settings;
import com.colasoft.opensearch.rest.RestController;
import com.colasoft.opensearch.rest.RestHandler;
import com.colasoft.opensearch.security.auditlog.AuditLog;
import com.colasoft.opensearch.security.configuration.AdminDNs;
import com.colasoft.opensearch.security.configuration.ConfigurationRepository;
import com.colasoft.opensearch.security.privileges.PrivilegesEvaluator;
import com.colasoft.opensearch.security.ssl.transport.PrincipalExtractor;
import com.colasoft.opensearch.threadpool.ThreadPool;

public class SecurityRestApiActions {

    public static Collection<RestHandler> getHandler(Settings settings, Path configPath, RestController controller, Client client,
                                                     AdminDNs adminDns, ConfigurationRepository cr, ClusterService cs, PrincipalExtractor principalExtractor,
                                                     final PrivilegesEvaluator evaluator, ThreadPool threadPool, AuditLog auditLog) {
        final List<RestHandler> handlers = new ArrayList<RestHandler>(15);
        handlers.add(new InternalUsersApiAction(settings, configPath, controller, client, adminDns, cr, cs, principalExtractor, evaluator, threadPool, auditLog));
        handlers.add(new RolesMappingApiAction(settings, configPath, controller, client, adminDns, cr, cs, principalExtractor, evaluator, threadPool, auditLog));
        handlers.add(new RolesApiAction(settings, configPath, controller, client, adminDns, cr, cs, principalExtractor, evaluator, threadPool, auditLog));
        handlers.add(new ActionGroupsApiAction(settings, configPath, controller, client, adminDns, cr, cs, principalExtractor, evaluator, threadPool, auditLog));
        handlers.add(new FlushCacheApiAction(settings, configPath, controller, client, adminDns, cr, cs, principalExtractor, evaluator, threadPool, auditLog));
        handlers.add(new SecurityConfigAction(settings, configPath, controller, client, adminDns, cr, cs, principalExtractor, evaluator, threadPool, auditLog));
        handlers.add(new PermissionsInfoAction(settings, configPath, controller, client, adminDns, cr, cs, principalExtractor, evaluator, threadPool, auditLog));
        handlers.add(new AuthTokenProcessorAction(settings, configPath, controller, client, adminDns, cr, cs, principalExtractor, evaluator, threadPool, auditLog));
        handlers.add(new TenantsApiAction(settings, configPath, controller, client, adminDns, cr, cs, principalExtractor, evaluator, threadPool, auditLog));
        handlers.add(new MigrateApiAction(settings, configPath, controller, client, adminDns, cr, cs, principalExtractor, evaluator, threadPool, auditLog));
        handlers.add(new ValidateApiAction(settings, configPath, controller, client, adminDns, cr, cs, principalExtractor, evaluator, threadPool, auditLog));
        handlers.add(new AccountApiAction(settings, configPath, controller, client, adminDns, cr, cs, principalExtractor, evaluator, threadPool, auditLog));
        handlers.add(new NodesDnApiAction(settings, configPath, controller, client, adminDns, cr, cs, principalExtractor, evaluator, threadPool, auditLog));
        handlers.add(new WhitelistApiAction(settings, configPath, controller, client, adminDns, cr, cs, principalExtractor, evaluator, threadPool, auditLog));
        handlers.add(new AllowlistApiAction(settings, configPath, controller, client, adminDns, cr, cs, principalExtractor, evaluator, threadPool, auditLog));
        handlers.add(new AuditApiAction(settings, configPath, controller, client, adminDns, cr, cs, principalExtractor, evaluator, threadPool, auditLog));
        return Collections.unmodifiableCollection(handlers);
    }

}
