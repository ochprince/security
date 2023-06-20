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
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnore;

import com.colasoft.opensearch.security.securityconf.Hashed;
import com.colasoft.opensearch.security.securityconf.Hideable;

public class InternalUserV6 implements Hideable, Hashed {
        
        private String hash;
        private boolean readonly;
        private boolean hidden;
        private List<String> roles = Collections.emptyList();
        private Map<String, String> attributes = Collections.emptyMap();
        private String username;

        

        public InternalUserV6(String hash, boolean readonly, boolean hidden, List<String> roles, Map<String, String> attributes, String username) {
            super();
            this.hash = hash;
            this.readonly = readonly;
            this.hidden = hidden;
            this.roles = roles;
            this.attributes = attributes;
            this.username = username;
        }

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public InternalUserV6() {
            super();
            //default constructor
        }
        
        public String getHash() {
            return hash;
        }
        public void setHash(String hash) {
            this.hash = hash;
        }

        public void setPassword(String password){
          // no-op setter. Due to a bug in 6.x, empty "password" may be saved to the internalusers doc. Ignore it.
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
        public List<String> getRoles() {
            return roles;
        }
        public void setRoles(List<String> roles) {
            this.roles = roles;
        }
        public Map<String, String> getAttributes() {
            return attributes;
        }
        public void setAttributes(Map<String, String> attributes) {
            this.attributes = attributes;
        }

        @Override
        public String toString() {
            return "SgInternalUser [hash=" + hash + ", readonly=" + readonly + ", hidden=" + hidden + ", roles=" + roles + ", attributes="
                    + attributes + "]";
        }
        
        @JsonIgnore
        public boolean isReserved() {
            return readonly;
        }

        @Override
        @JsonIgnore
        public void clearHash() {
            hash = "";
        }
        
        

    }
