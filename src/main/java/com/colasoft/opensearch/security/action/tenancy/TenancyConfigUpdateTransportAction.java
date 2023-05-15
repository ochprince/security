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

package com.colasoft.opensearch.security.action.tenancy;

import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.colasoft.opensearch.action.ActionListener;
import com.colasoft.opensearch.action.index.IndexResponse;
import com.colasoft.opensearch.action.support.ActionFilters;
import com.colasoft.opensearch.action.support.HandledTransportAction;
import com.colasoft.opensearch.client.Client;
import com.colasoft.opensearch.common.inject.Inject;
import com.colasoft.opensearch.common.settings.Settings;
import com.colasoft.opensearch.common.util.concurrent.ThreadContext;
import com.colasoft.opensearch.security.configuration.ConfigurationRepository;
import com.colasoft.opensearch.security.dlic.rest.api.AbstractApiAction;
import com.colasoft.opensearch.security.securityconf.impl.CType;
import com.colasoft.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import com.colasoft.opensearch.security.securityconf.impl.v7.ConfigV7;
import com.colasoft.opensearch.security.support.ConfigConstants;
import com.colasoft.opensearch.tasks.Task;
import com.colasoft.opensearch.threadpool.ThreadPool;
import com.colasoft.opensearch.transport.TransportService;

public class TenancyConfigUpdateTransportAction extends HandledTransportAction<TenancyConfigUpdateRequest, TenancyConfigRetrieveResponse> {

    private static final Logger log = LogManager.getLogger(TenancyConfigUpdateTransportAction.class);

    private final String securityIndex;
    private final ConfigurationRepository config;
    private final Client client;
    private final ThreadPool pool;

    @Inject
    public TenancyConfigUpdateTransportAction(final Settings settings,
                                              final TransportService transportService,
                                              final ActionFilters actionFilters,
                                              final ConfigurationRepository config,
                                              final ThreadPool pool,
                                              final Client client) {
        super(TenancyConfigUpdateAction.NAME, transportService, actionFilters, TenancyConfigUpdateRequest::new);

        this.securityIndex = settings.get(ConfigConstants.SECURITY_CONFIG_INDEX_NAME, ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX);

        this.config = config;
        this.client = client;
        this.pool = pool;
    }

    /** Load the configuration from the security index and return a copy */
    protected final SecurityDynamicConfiguration<?> load() {
        return config.getConfigurationsFromIndex(Collections.singleton(CType.CONFIG), false).get(CType.CONFIG).deepClone();
    }

    private Set<String> getAcceptableDefaultTenants() {
        Set<String> acceptableDefaultTenants = new HashSet<String>();
        acceptableDefaultTenants.add(ConfigConstants.TENANCY_GLOBAL_TENANT_DEFAULT_NAME);
        acceptableDefaultTenants.add(ConfigConstants.TENANCY_GLOBAL_TENANT_NAME);
        acceptableDefaultTenants.add(ConfigConstants.TENANCY_PRIVATE_TENANT_NAME);
        return acceptableDefaultTenants;
    }

    private Set<String> getAllConfiguredTenantNames() {

        return this.config.getConfiguration(CType.TENANTS).getCEntries().keySet();
    }

    protected void validate(ConfigV7 updatedConfig) {
        if(!updatedConfig.dynamic.kibana.private_tenant_enabled && (updatedConfig.dynamic.kibana.default_tenant).equals(ConfigConstants.TENANCY_PRIVATE_TENANT_NAME)) {
            throw new IllegalArgumentException("Private tenant can not be disabled if it is the default tenant.");
        }

        Set<String> acceptableDefaultTenants = getAcceptableDefaultTenants();

        if(acceptableDefaultTenants.contains(updatedConfig.dynamic.kibana.default_tenant)) {
            return;
        }

        Set<String> availableTenants = getAllConfiguredTenantNames();

        if(!availableTenants.contains(updatedConfig.dynamic.kibana.default_tenant)){
            throw new IllegalArgumentException(updatedConfig.dynamic.kibana.default_tenant + " can not be set to default tenant. Default tenant should be selected from one of the available tenants.");
        }

    }

    @Override
    protected void doExecute(final Task task, final TenancyConfigUpdateRequest request, final ActionListener<TenancyConfigRetrieveResponse> listener) {

        // Get the current security config and prepare the config with the updated value
        final SecurityDynamicConfiguration dynamicConfig = load();
        final ConfigV7 config = (ConfigV7)dynamicConfig.getCEntry("config");

        final TenancyConfigs tenancyConfigs = request.getTenancyConfigs();
        if(tenancyConfigs.multitenancy_enabled != null)
        {
            config.dynamic.kibana.multitenancy_enabled = tenancyConfigs.multitenancy_enabled;
        }

        if(tenancyConfigs.private_tenant_enabled != null)
        {
            config.dynamic.kibana.private_tenant_enabled = tenancyConfigs.private_tenant_enabled;
        }

        if(tenancyConfigs.default_tenant != null)
        {
            config.dynamic.kibana.default_tenant = tenancyConfigs.default_tenant;
        }

        validate(config);

        dynamicConfig.putCEntry("config", config);

        // When performing an update to the configuration run as admin
        try (final ThreadContext.StoredContext stashedContext = pool.getThreadContext().stashContext()) {
            // Update the security configuration and make sure the cluster has fully refreshed
            AbstractApiAction.saveAndUpdateConfigs(this.securityIndex, this.client, CType.CONFIG, dynamicConfig, new ActionListener<IndexResponse>(){

                @Override
                public void onResponse(final IndexResponse response) {
                    // After processing the request, restore the user context
                    stashedContext.close();
                    try {
                        // Lookup the current value and notify the listener
                        client.execute(TenancyConfigRetrieveActions.INSTANCE, new EmptyRequest(), listener);
                    } catch (IOException ioe) {
                        log.error(ioe);
                        listener.onFailure(ioe);
                    }
                }

                @Override
                public void onFailure(Exception e) {
                    log.error(e);
                    listener.onFailure(e);
                }
            });
        }
    }
}
