/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The ColaSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

/*
 * Copyright 2015-2017 floragunn GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
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

package com.colasoft.opensearch.security.securityconf;

import java.util.Set;

import com.colasoft.opensearch.cluster.metadata.IndexNameExpressionResolver;
import com.colasoft.opensearch.cluster.service.ClusterService;
import com.colasoft.opensearch.core.xcontent.NamedXContentRegistry;
import com.colasoft.opensearch.security.resolver.IndexResolverReplacer.Resolved;
import com.colasoft.opensearch.security.user.User;

public interface SecurityRoles {

    boolean impliesClusterPermissionPermission(String action0);

    Set<String> getRoleNames();

    Set<String> reduce(Resolved requestedResolved, User user, String[] strings, IndexNameExpressionResolver resolver, ClusterService clusterService);

    boolean impliesTypePermGlobal(Resolved requestedResolved, User user, String[] allIndexPermsRequiredA, IndexNameExpressionResolver resolver, ClusterService clusterService);

    boolean get(Resolved requestedResolved, User user, String[] allIndexPermsRequiredA, IndexNameExpressionResolver resolver, ClusterService clusterService);

    EvaluatedDlsFlsConfig getDlsFls(User user, boolean dfmEmptyOverwritesAll, IndexNameExpressionResolver resolver, ClusterService clusterService, NamedXContentRegistry namedXContentRegistry);

    Set<String> getAllPermittedIndicesForDashboards(Resolved resolved, User user, String[] actions, IndexNameExpressionResolver resolver, ClusterService cs);

    SecurityRoles filter(Set<String> roles);

}
