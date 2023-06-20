/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The ColaSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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

package com.colasoft.opensearch.security.action.whoami;

import com.colasoft.opensearch.action.ActionListener;
import com.colasoft.opensearch.action.support.ActionFilters;
import com.colasoft.opensearch.action.support.HandledTransportAction;
import com.colasoft.opensearch.cluster.service.ClusterService;
import com.colasoft.opensearch.common.inject.Inject;
import com.colasoft.opensearch.common.settings.Settings;
import com.colasoft.opensearch.security.configuration.AdminDNs;
import com.colasoft.opensearch.security.support.ConfigConstants;
import com.colasoft.opensearch.security.support.HeaderHelper;
import com.colasoft.opensearch.security.user.User;
import com.colasoft.opensearch.tasks.Task;
import com.colasoft.opensearch.threadpool.ThreadPool;
import com.colasoft.opensearch.transport.TransportService;

public class TransportWhoAmIAction
extends
HandledTransportAction<WhoAmIRequest, WhoAmIResponse> {

    private final AdminDNs adminDNs;
    private final ThreadPool threadPool;

    @Inject
    public TransportWhoAmIAction(final Settings settings,
            final ThreadPool threadPool, final ClusterService clusterService, final TransportService transportService,
            final AdminDNs adminDNs, final ActionFilters actionFilters) {

        super(WhoAmIAction.NAME, transportService, actionFilters, WhoAmIRequest::new);

        this.adminDNs = adminDNs;
        this.threadPool = threadPool;
    }


    @Override
    protected void doExecute(Task task, WhoAmIRequest request, ActionListener<WhoAmIResponse> listener) {
        final User user = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        final String dn = user==null?threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PRINCIPAL):user.getName();
        final boolean isAdmin = adminDNs.isAdminDN(dn);
        final boolean isAuthenticated = isAdmin?true: user != null;
        final boolean isNodeCertificateRequest = HeaderHelper.isInterClusterRequest(threadPool.getThreadContext()) || 
                HeaderHelper.isTrustedClusterRequest(threadPool.getThreadContext());
        
        listener.onResponse(new WhoAmIResponse(dn, isAdmin, isAuthenticated, isNodeCertificateRequest));
        
    }
}
