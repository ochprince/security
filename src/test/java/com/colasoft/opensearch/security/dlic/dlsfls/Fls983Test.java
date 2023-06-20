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

package com.colasoft.opensearch.security.dlic.dlsfls;

import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import com.colasoft.opensearch.action.index.IndexRequest;
import com.colasoft.opensearch.action.support.WriteRequest.RefreshPolicy;
import com.colasoft.opensearch.client.Client;
import com.colasoft.opensearch.common.xcontent.XContentType;
import com.colasoft.opensearch.security.test.DynamicSecurityConfig;
import com.colasoft.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

public class Fls983Test extends AbstractDlsFlsTest{


    protected void populateData(Client tc) {

        tc.index(new IndexRequest(".kibana").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{}", XContentType.JSON)).actionGet();
    }

    @Test
    public void test() throws Exception {

        setup(new DynamicSecurityConfig().setSecurityRoles("roles_983.yml"));

        HttpResponse res;

        String doc =  "{\"doc\" : {"+
            "\"x\" : \"y\""+
        "}}";

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executePostRequest("/.kibana/_update/0?pretty", doc, encodeBasicHeader("human_resources_trainee", "password"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains("updated"));
        Assert.assertTrue(res.getBody().contains("\"failed\" : 0"));
    }
}
