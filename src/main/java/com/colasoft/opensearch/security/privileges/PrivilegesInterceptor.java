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

package com.colasoft.opensearch.security.privileges;

import java.util.Map;

import com.colasoft.opensearch.action.ActionRequest;
import com.colasoft.opensearch.action.admin.indices.create.CreateIndexRequestBuilder;
import com.colasoft.opensearch.client.Client;
import com.colasoft.opensearch.cluster.metadata.IndexNameExpressionResolver;
import com.colasoft.opensearch.cluster.service.ClusterService;
import com.colasoft.opensearch.common.util.concurrent.ThreadContext;
import com.colasoft.opensearch.security.resolver.IndexResolverReplacer.Resolved;
import com.colasoft.opensearch.security.securityconf.DynamicConfigModel;
import com.colasoft.opensearch.security.user.User;
import com.colasoft.opensearch.threadpool.ThreadPool;

public class PrivilegesInterceptor {

    public static class ReplaceResult {
        final boolean continueEvaluation;
        final boolean accessDenied;
        final CreateIndexRequestBuilder createIndexRequestBuilder;

        private ReplaceResult(boolean continueEvaluation, boolean accessDenied, CreateIndexRequestBuilder createIndexRequestBuilder) {
            this.continueEvaluation = continueEvaluation;
            this.accessDenied = accessDenied;
            this.createIndexRequestBuilder = createIndexRequestBuilder;
        }
    }

    public static final ReplaceResult CONTINUE_EVALUATION_REPLACE_RESULT = new ReplaceResult(true, false, null);
    public static final ReplaceResult ACCESS_DENIED_REPLACE_RESULT = new ReplaceResult(false, true, null);
    public static final ReplaceResult ACCESS_GRANTED_REPLACE_RESULT = new ReplaceResult(false, false, null);
    protected static ReplaceResult newAccessGrantedReplaceResult(CreateIndexRequestBuilder createIndexRequestBuilder) {
        return new ReplaceResult(false, false, createIndexRequestBuilder);
    }

    protected final IndexNameExpressionResolver resolver;
    protected final ClusterService clusterService;
    protected final Client client;
    protected final ThreadPool threadPool;

    public PrivilegesInterceptor(final IndexNameExpressionResolver resolver, final ClusterService clusterService, 
            final Client client, ThreadPool threadPool) {
        this.resolver = resolver;
        this.clusterService = clusterService;
        this.client = client;
        this.threadPool = threadPool;
    }

    public ReplaceResult replaceDashboardsIndex(final ActionRequest request, final String action, final User user, final DynamicConfigModel config,
                                                final Resolved requestedResolved, final Map<String, Boolean> tenants) {
        throw new RuntimeException("not implemented");
    }
    
    protected final ThreadContext getThreadContext() {
        return threadPool.getThreadContext();
    }
}
