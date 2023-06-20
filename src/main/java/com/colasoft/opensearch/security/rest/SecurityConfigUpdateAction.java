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

package com.colasoft.opensearch.security.rest;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

import com.google.common.collect.ImmutableList;

import com.colasoft.opensearch.client.node.NodeClient;
import com.colasoft.opensearch.common.settings.Settings;
import com.colasoft.opensearch.common.util.concurrent.ThreadContext;
import com.colasoft.opensearch.rest.BaseRestHandler;
import com.colasoft.opensearch.rest.BytesRestResponse;
import com.colasoft.opensearch.rest.RestController;
import com.colasoft.opensearch.rest.RestRequest;
import com.colasoft.opensearch.rest.RestStatus;
import com.colasoft.opensearch.rest.action.RestActions.NodesResponseRestListener;
import com.colasoft.opensearch.security.action.configupdate.ConfigUpdateAction;
import com.colasoft.opensearch.security.action.configupdate.ConfigUpdateRequest;
import com.colasoft.opensearch.security.configuration.AdminDNs;
import com.colasoft.opensearch.security.ssl.transport.PrincipalExtractor;
import com.colasoft.opensearch.security.ssl.util.SSLRequestHelper;
import com.colasoft.opensearch.security.support.ConfigConstants;
import com.colasoft.opensearch.security.user.User;
import com.colasoft.opensearch.threadpool.ThreadPool;

import static com.colasoft.opensearch.rest.RestRequest.Method.PUT;
import static com.colasoft.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class SecurityConfigUpdateAction extends BaseRestHandler {

    private static final List<Route> routes = addRoutesPrefix(ImmutableList.of(
            new Route(PUT, "/configupdate")),
            "/_plugins/_security");

    private final ThreadContext threadContext;
    private final AdminDNs adminDns;
    private final Settings settings;
    private final Path configPath;
    private final PrincipalExtractor principalExtractor;

    public SecurityConfigUpdateAction(final Settings settings, final RestController controller, final ThreadPool threadPool, final AdminDNs adminDns,
            Path configPath, PrincipalExtractor principalExtractor) {
        super();
        this.threadContext = threadPool.getThreadContext();
        this.adminDns = adminDns;
        this.settings = settings;
        this.configPath = configPath;
        this.principalExtractor = principalExtractor;
    }

    @Override public List<Route> routes() {
        return routes;
    }

    @Override protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        String[] configTypes = request.paramAsStringArrayOrEmptyIfAll("config_types");

        SSLRequestHelper.SSLInfo sslInfo = SSLRequestHelper.getSSLInfo(settings, configPath, request, principalExtractor);

        if (sslInfo == null) {
            return channel -> channel.sendResponse(new BytesRestResponse(RestStatus.FORBIDDEN, ""));
        }

        final User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);

        //only allowed for admins
        if (user == null || !adminDns.isAdmin(user)) {
            return channel -> channel.sendResponse(new BytesRestResponse(RestStatus.FORBIDDEN, ""));
        } else {
            ConfigUpdateRequest configUpdateRequest = new ConfigUpdateRequest(configTypes);
            return channel -> {
                client.execute(ConfigUpdateAction.INSTANCE, configUpdateRequest, new NodesResponseRestListener<>(channel));
            };
        }
    }

    @Override public String getName() {
        return "Security config update";
    }

}
