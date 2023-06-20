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

package com.colasoft.opensearch.security.securityconf.impl.v6;

import java.util.Collections;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import com.colasoft.opensearch.security.securityconf.Hideable;
import com.colasoft.opensearch.security.securityconf.RoleMappings;

public class RoleMappingsV6 extends RoleMappings implements Hideable {

    private boolean readonly;
    private boolean hidden;
    private List<String> backendroles = Collections.emptyList();
    private List<String> andBackendroles= Collections.emptyList();




    public RoleMappingsV6() {
        super();
    }

    public boolean isReadonly() {
        return readonly;
    }
    public void setReadonly(boolean readonly) {
        this.readonly = readonly;
    }
    public boolean isHidden() {
        return hidden;
    }
    public void setHidden(boolean hidden) {
        this.hidden = hidden;
    }
    public List<String> getBackendroles() {
        return backendroles;
    }
    public void setBackendroles(List<String> backendroles) {
        this.backendroles = backendroles;
    }

    @JsonProperty(value="and_backendroles")
    public List<String> getAndBackendroles() {
        return andBackendroles;
    }
    public void setAndBackendroles(List<String> andBackendroles) {
        this.andBackendroles = andBackendroles;
    }

    @Override
    public String toString() {
        return "RoleMappings [readonly=" + readonly + ", hidden=" + hidden + ", backendroles=" + backendroles + ", hosts=" + getHosts() + ", users="
                + getUsers() + ", andBackendroles=" + andBackendroles + "]";
    }
    
    @JsonIgnore
    public boolean isReserved() {
        return readonly;
    }

}
