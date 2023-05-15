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

import java.util.Collections;

import com.colasoft.opensearch.action.ActionListener;
import com.colasoft.opensearch.action.support.ActionFilters;
import com.colasoft.opensearch.action.support.HandledTransportAction;
import com.colasoft.opensearch.common.inject.Inject;
import com.colasoft.opensearch.common.settings.Settings;
import com.colasoft.opensearch.security.configuration.ConfigurationRepository;
import com.colasoft.opensearch.security.securityconf.impl.CType;
import com.colasoft.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import com.colasoft.opensearch.security.securityconf.impl.v7.ConfigV7;
import com.colasoft.opensearch.tasks.Task;
import com.colasoft.opensearch.transport.TransportService;

public class TenancyConfigRetrieveTransportAction
        extends HandledTransportAction<EmptyRequest, TenancyConfigRetrieveResponse> {

    private final ConfigurationRepository config;

    @Inject
    public TenancyConfigRetrieveTransportAction(final Settings settings,
                                                final TransportService transportService,
                                                final ActionFilters actionFilters,
                                                final ConfigurationRepository config) {
        super(TenancyConfigRetrieveActions.NAME, transportService, actionFilters, EmptyRequest::new);

        this.config = config;
    }

    /** Load the configuration from the security index and return a copy */
    protected final SecurityDynamicConfiguration<?> load() {
        return config.getConfigurationsFromIndex(Collections.singleton(CType.CONFIG), false).get(CType.CONFIG).deepClone();
    }

    @Override
    protected void doExecute(final Task task, final EmptyRequest request, final ActionListener<TenancyConfigRetrieveResponse> listener) {

        // Get the security configuration and lookup the config setting state
        final SecurityDynamicConfiguration<?> dynamicConfig = load();
        ConfigV7 config = (ConfigV7)dynamicConfig.getCEntry("config");

        final TenancyConfigs tenancyConfigs= new TenancyConfigs();

        tenancyConfigs.multitenancy_enabled = config.dynamic.kibana.multitenancy_enabled;
        tenancyConfigs.private_tenant_enabled = config.dynamic.kibana.private_tenant_enabled;
        tenancyConfigs.default_tenant = config.dynamic.kibana.default_tenant;

        listener.onResponse(new TenancyConfigRetrieveResponse(tenancyConfigs));
    }
}
