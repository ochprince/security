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

package com.colasoft.opensearch.security.test.plugin;

import java.nio.file.Path;
import java.util.Map;
import java.util.function.Supplier;

import com.google.common.collect.ImmutableMap;

import com.colasoft.opensearch.common.network.NetworkService;
import com.colasoft.opensearch.common.settings.ClusterSettings;
import com.colasoft.opensearch.common.settings.Settings;
import com.colasoft.opensearch.common.util.BigArrays;
import com.colasoft.opensearch.common.util.PageCacheRecycler;
import com.colasoft.opensearch.common.util.concurrent.ThreadContext;
import com.colasoft.opensearch.common.xcontent.NamedXContentRegistry;
import com.colasoft.opensearch.http.HttpServerTransport;
import com.colasoft.opensearch.http.HttpServerTransport.Dispatcher;
import com.colasoft.opensearch.http.netty4.Netty4HttpServerTransport;
import com.colasoft.opensearch.indices.breaker.CircuitBreakerService;
import com.colasoft.opensearch.plugins.NetworkPlugin;
import com.colasoft.opensearch.plugins.Plugin;
import com.colasoft.opensearch.rest.RestChannel;
import com.colasoft.opensearch.rest.RestRequest;
import com.colasoft.opensearch.security.support.ConfigConstants;
import com.colasoft.opensearch.threadpool.ThreadPool;
import com.colasoft.opensearch.transport.SharedGroupFactory;

/**
 * Mimics the behavior of system integrators that run their own plugins (i.e. server transports)
 * in front of OpenSearch Security. This transport just copies the user string from the
 * REST headers to the ThreadContext to test user injection.
 * @author jkressin
 */
public class UserInjectorPlugin extends Plugin implements NetworkPlugin {
    
    Settings settings;
    private final SharedGroupFactory sharedGroupFactory;
    ThreadPool threadPool;
    
    public UserInjectorPlugin(final Settings settings, final Path configPath) {        
        this.settings = settings;
        sharedGroupFactory = new SharedGroupFactory(settings);
    }

    @Override
    public Map<String, Supplier<HttpServerTransport>> getHttpTransports(Settings settings, ThreadPool threadPool, BigArrays bigArrays,
            PageCacheRecycler pageCacheRecycler, CircuitBreakerService circuitBreakerService, NamedXContentRegistry xContentRegistry,
            NetworkService networkService, Dispatcher dispatcher, ClusterSettings clusterSettings) {

        final UserInjectingDispatcher validatingDispatcher = new UserInjectingDispatcher(dispatcher);
        return ImmutableMap.of("com.colasoft.opensearch.security.http.UserInjectingServerTransport",
                () -> new UserInjectingServerTransport(settings, networkService, bigArrays, threadPool, xContentRegistry, validatingDispatcher, clusterSettings, sharedGroupFactory));
    }
    
    class UserInjectingServerTransport extends Netty4HttpServerTransport {
        
        public UserInjectingServerTransport(final Settings settings, final NetworkService networkService, final BigArrays bigArrays,
                                            final ThreadPool threadPool, final NamedXContentRegistry namedXContentRegistry, final Dispatcher dispatcher, ClusterSettings clusterSettings, SharedGroupFactory sharedGroupFactory) {
            super(settings, networkService, bigArrays, threadPool, namedXContentRegistry, dispatcher, clusterSettings, sharedGroupFactory);
        }
    }
    
    class UserInjectingDispatcher implements Dispatcher {
        
        private Dispatcher originalDispatcher;

        public UserInjectingDispatcher(final Dispatcher originalDispatcher) {
            super();
            this.originalDispatcher = originalDispatcher;
        }

        @Override
        public void dispatchRequest(RestRequest request, RestChannel channel, ThreadContext threadContext) {
            threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, request.header(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER));
            originalDispatcher.dispatchRequest(request, channel, threadContext);
            
        }

        @Override
        public void dispatchBadRequest(RestChannel channel, ThreadContext threadContext, Throwable cause) {
            threadContext.putTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, channel.request().header(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER));
            originalDispatcher.dispatchBadRequest(channel, threadContext, cause);
        }
    }

}
