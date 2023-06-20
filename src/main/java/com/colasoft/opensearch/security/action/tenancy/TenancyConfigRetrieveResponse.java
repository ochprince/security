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

package com.colasoft.opensearch.security.action.tenancy;

import java.io.IOException;

import com.colasoft.opensearch.action.ActionResponse;
import com.colasoft.opensearch.common.Strings;
import com.colasoft.opensearch.common.io.stream.StreamInput;
import com.colasoft.opensearch.common.io.stream.StreamOutput;
import com.colasoft.opensearch.common.xcontent.XContentType;
import com.colasoft.opensearch.core.xcontent.ToXContentObject;
import com.colasoft.opensearch.core.xcontent.XContentBuilder;

public class TenancyConfigRetrieveResponse extends ActionResponse implements ToXContentObject {

    public TenancyConfigs tenancyConfigs = new TenancyConfigs();

    public TenancyConfigRetrieveResponse(final StreamInput in) throws IOException {
        super(in);
        this.tenancyConfigs.multitenancy_enabled = in.readOptionalBoolean();
        this.tenancyConfigs.private_tenant_enabled = in.readOptionalBoolean();
        this.tenancyConfigs.default_tenant = in.readOptionalString();
    }

    public TenancyConfigRetrieveResponse(final TenancyConfigs tenancyConfigs) {
        this.tenancyConfigs = tenancyConfigs;
    }

    public TenancyConfigs getMultitenancyConfig() {
        return tenancyConfigs;
    }

    public Boolean getMultitenancyEnabled() { return tenancyConfigs.multitenancy_enabled; }

    public Boolean getPrivateTenantEnabled() { return tenancyConfigs.private_tenant_enabled; }

    public String getDefaultTenant() { return tenancyConfigs.default_tenant; }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        out.writeBoolean(getMultitenancyEnabled());
        out.writeBoolean(getPrivateTenantEnabled());
        out.writeString(getDefaultTenant());
    }

    @Override
    public String toString() {
        return Strings.toString(XContentType.JSON, this, true, true);
    }

    @Override
    public XContentBuilder toXContent(final XContentBuilder builder, final Params params) throws IOException {
        builder.startObject();
        builder.field("multitenancy_enabled", getMultitenancyEnabled());
        builder.field("private_tenant_enabled", getPrivateTenantEnabled());
        builder.field("default_tenant", getDefaultTenant());
        builder.endObject();
        return builder;
    }
}
