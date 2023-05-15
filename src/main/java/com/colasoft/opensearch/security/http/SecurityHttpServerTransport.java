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

package com.colasoft.opensearch.security.http;

import com.colasoft.opensearch.common.network.NetworkService;
import com.colasoft.opensearch.common.settings.ClusterSettings;
import com.colasoft.opensearch.common.settings.Settings;
import com.colasoft.opensearch.common.util.BigArrays;
import com.colasoft.opensearch.core.xcontent.NamedXContentRegistry;
import com.colasoft.opensearch.security.ssl.SecurityKeyStore;
import com.colasoft.opensearch.security.ssl.SslExceptionHandler;
import com.colasoft.opensearch.security.ssl.http.netty.SecuritySSLNettyHttpServerTransport;
import com.colasoft.opensearch.security.ssl.http.netty.ValidatingDispatcher;
import com.colasoft.opensearch.threadpool.ThreadPool;
import com.colasoft.opensearch.transport.SharedGroupFactory;

public class SecurityHttpServerTransport extends SecuritySSLNettyHttpServerTransport {
    
    public SecurityHttpServerTransport(final Settings settings, final NetworkService networkService,
                                       final BigArrays bigArrays, final ThreadPool threadPool, final SecurityKeyStore odsks,
                                       final SslExceptionHandler sslExceptionHandler, final NamedXContentRegistry namedXContentRegistry, final ValidatingDispatcher dispatcher, final ClusterSettings clusterSettings, SharedGroupFactory sharedGroupFactory) {
        super(settings, networkService, bigArrays, threadPool, odsks, namedXContentRegistry, dispatcher, sslExceptionHandler, clusterSettings, sharedGroupFactory);
    }
}
