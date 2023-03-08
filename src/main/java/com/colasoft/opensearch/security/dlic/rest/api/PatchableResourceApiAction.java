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

package com.colasoft.opensearch.security.dlic.rest.api;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Iterator;
import java.util.List;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.flipkart.zjsonpatch.JsonPatch;
import com.flipkart.zjsonpatch.JsonPatchApplicationException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.colasoft.opensearch.action.index.IndexResponse;
import com.colasoft.opensearch.client.Client;
import com.colasoft.opensearch.cluster.service.ClusterService;
import com.colasoft.opensearch.common.Strings;
import com.colasoft.opensearch.common.bytes.BytesArray;
import com.colasoft.opensearch.common.bytes.BytesReference;
import com.colasoft.opensearch.common.settings.Settings;
import com.colasoft.opensearch.common.xcontent.XContentType;
import com.colasoft.opensearch.rest.RestChannel;
import com.colasoft.opensearch.rest.RestController;
import com.colasoft.opensearch.rest.RestRequest;
import com.colasoft.opensearch.rest.RestRequest.Method;
import com.colasoft.opensearch.security.DefaultObjectMapper;
import com.colasoft.opensearch.security.auditlog.AuditLog;
import com.colasoft.opensearch.security.configuration.AdminDNs;
import com.colasoft.opensearch.security.configuration.ConfigurationRepository;
import com.colasoft.opensearch.security.dlic.rest.support.Utils;
import com.colasoft.opensearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import com.colasoft.opensearch.security.privileges.PrivilegesEvaluator;
import com.colasoft.opensearch.security.securityconf.impl.CType;
import com.colasoft.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import com.colasoft.opensearch.security.securityconf.impl.v7.ActionGroupsV7;
import com.colasoft.opensearch.security.ssl.transport.PrincipalExtractor;
import com.colasoft.opensearch.threadpool.ThreadPool;

public abstract class PatchableResourceApiAction extends AbstractApiAction {

    protected final Logger log = LogManager.getLogger(this.getClass());

    public PatchableResourceApiAction(Settings settings, Path configPath, RestController controller, Client client,
                                      AdminDNs adminDNs, ConfigurationRepository cl, ClusterService cs,
                                      PrincipalExtractor principalExtractor, PrivilegesEvaluator evaluator, ThreadPool threadPool,
                                      AuditLog auditLog) {
        super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool,
                auditLog);
    }

    private void handlePatch(RestChannel channel, final RestRequest request, final Client client)
            throws IOException  {
        if (request.getXContentType() != XContentType.JSON) {
            badRequestResponse(channel, "PATCH accepts only application/json");
            return;
        }

        String name = request.param("name");
        SecurityDynamicConfiguration<?> existingConfiguration = load(getConfigName(), false);

        if (existingConfiguration.getSeqNo() < 0) {
            forbidden(channel, "Config '" + getConfigName().toLCString() + "' isn't configured. Use SecurityAdmin to populate.");
            return;
        }

        JsonNode jsonPatch;

        try {
            jsonPatch = DefaultObjectMapper.readTree(request.content().utf8ToString());
        } catch (IOException e) {
            log.debug("Error while parsing JSON patch", e);
            badRequestResponse(channel, "Error in JSON patch: " + e.getMessage());
            return;
        }

        JsonNode existingAsJsonNode = Utils.convertJsonToJackson(existingConfiguration, true);

        if (!(existingAsJsonNode instanceof ObjectNode)) {
            internalErrorResponse(channel, "Config " + getConfigName() + " is malformed");
            return;
        }

        ObjectNode existingAsObjectNode = (ObjectNode) existingAsJsonNode;

        if (Strings.isNullOrEmpty(name)) {
            handleBulkPatch(channel, request, client, existingConfiguration, existingAsObjectNode, jsonPatch);
        } else {
            handleSinglePatch(channel, request, client, name, existingConfiguration, existingAsObjectNode, jsonPatch);
        }
    }

    private void handleSinglePatch(RestChannel channel, RestRequest request, Client client, String name,
            SecurityDynamicConfiguration<?> existingConfiguration, ObjectNode existingAsObjectNode, JsonNode jsonPatch) throws IOException {
        if (!isWriteable(channel, existingConfiguration, name)) {
            return;
        }

        if (!existingConfiguration.exists(name)) {
            notFound(channel, getResourceName() + " " + name + " not found.");
            return;
        }

        JsonNode existingResourceAsJsonNode = existingAsObjectNode.get(name);

        JsonNode patchedResourceAsJsonNode;

        try {
            patchedResourceAsJsonNode = applyPatch(jsonPatch, existingResourceAsJsonNode);
        } catch (JsonPatchApplicationException e) {
            log.debug("Error while applying JSON patch", e);
            badRequestResponse(channel, e.getMessage());
            return;
        }

        AbstractConfigurationValidator originalValidator = postProcessApplyPatchResult(channel, request, existingResourceAsJsonNode, patchedResourceAsJsonNode, name);

        if(originalValidator != null) {
            if (!originalValidator.validate()) {
                request.params().clear();
                badRequestResponse(channel, originalValidator);
                return;
            }
        }

        if (isReadonlyFieldUpdated(existingResourceAsJsonNode, patchedResourceAsJsonNode)) {
            request.params().clear();
            conflict(channel, "Attempted to update read-only property.");
            return;
        }

        AbstractConfigurationValidator validator = getValidator(request, patchedResourceAsJsonNode);

        if (!validator.validate()) {
            request.params().clear();
                badRequestResponse(channel, validator);
            return;
        }

        JsonNode updatedAsJsonNode = existingAsObjectNode.deepCopy().set(name, patchedResourceAsJsonNode);

        SecurityDynamicConfiguration<?> mdc = SecurityDynamicConfiguration.fromNode(updatedAsJsonNode, existingConfiguration.getCType()
                                   , existingConfiguration.getVersion(), existingConfiguration.getSeqNo(), existingConfiguration.getPrimaryTerm());

        if (existingConfiguration.getCType().equals(CType.ACTIONGROUPS)) {
            if(hasActionGroupSelfReference(mdc, name)) {
                badRequestResponse(channel, name + " cannot be an allowed_action of itself");
                return;
            }
        }

        saveAnUpdateConfigs(client, request, getConfigName(), mdc, new OnSucessActionListener<IndexResponse>(channel){

            @Override
            public void onResponse(IndexResponse response) {
                successResponse(channel, "'" + name + "' updated.");

            }
            });
    }

    private void handleBulkPatch(RestChannel channel, RestRequest request, Client client,
            SecurityDynamicConfiguration<?> existingConfiguration, ObjectNode existingAsObjectNode, JsonNode jsonPatch) throws IOException {

        JsonNode patchedAsJsonNode;

        try {
            patchedAsJsonNode = applyPatch(jsonPatch, existingAsObjectNode);
        } catch (JsonPatchApplicationException e) {
            log.debug("Error while applying JSON patch", e);
            badRequestResponse(channel, e.getMessage());
            return;
        }

        for (String resourceName : existingConfiguration.getCEntries().keySet()) {
            JsonNode oldResource = existingAsObjectNode.get(resourceName);
            JsonNode patchedResource = patchedAsJsonNode.get(resourceName);

            if (oldResource != null && !oldResource.equals(patchedResource) && !isWriteable(channel, existingConfiguration, resourceName)) {
                return;
            }
        }


        for (Iterator<String> fieldNamesIter = patchedAsJsonNode.fieldNames(); fieldNamesIter.hasNext();) {
            String resourceName = fieldNamesIter.next();

            JsonNode oldResource = existingAsObjectNode.get(resourceName);
            JsonNode patchedResource = patchedAsJsonNode.get(resourceName);

            AbstractConfigurationValidator originalValidator = postProcessApplyPatchResult(channel, request, oldResource, patchedResource, resourceName);

            if(originalValidator != null) {
                if (!originalValidator.validate()) {
                    request.params().clear();
                        badRequestResponse(channel, originalValidator);
                    return;
                }
            }

            if (isReadonlyFieldUpdated(oldResource, patchedResource)) {
                request.params().clear();
                conflict(channel, "Attempted to update read-only property.");
                return;
            }

            if (oldResource == null || !oldResource.equals(patchedResource)) {
                AbstractConfigurationValidator validator = getValidator(request, patchedResource);

                if (!validator.validate()) {
                    request.params().clear();
                        badRequestResponse(channel, validator);
                    return;
                }
            }
        }
        SecurityDynamicConfiguration<?> mdc = SecurityDynamicConfiguration.fromNode(patchedAsJsonNode, existingConfiguration.getCType()
                                    , existingConfiguration.getVersion(), existingConfiguration.getSeqNo(), existingConfiguration.getPrimaryTerm());

        if (existingConfiguration.getCType().equals(CType.ACTIONGROUPS)) {
            for (String actiongroup : mdc.getCEntries().keySet()) {
                if(hasActionGroupSelfReference(mdc, actiongroup)) {
                    badRequestResponse(channel, actiongroup + " cannot be an allowed_action of itself");
                    return;
                }
            }
        }

        saveAnUpdateConfigs(client, request, getConfigName(), mdc, new OnSucessActionListener<IndexResponse>(channel) {

            @Override
            public void onResponse(IndexResponse response) {
                successResponse(channel, "Resource updated.");
            }
            });

    }

    private JsonNode applyPatch(JsonNode jsonPatch, JsonNode existingResourceAsJsonNode) {
        return JsonPatch.apply(jsonPatch, existingResourceAsJsonNode);
    }

    protected AbstractConfigurationValidator postProcessApplyPatchResult(RestChannel channel, RestRequest request, JsonNode existingResourceAsJsonNode, JsonNode updatedResourceAsJsonNode, String resourceName) {
        // do nothing by default
        return null;
    }

    @Override
    protected void handleApiRequest(RestChannel channel, final RestRequest request, final Client client)
            throws IOException {

        if (request.method() == Method.PATCH) {
            handlePatch(channel, request, client);
        } else {
            super.handleApiRequest(channel, request, client);
        }
    }

    private AbstractConfigurationValidator getValidator(RestRequest request, JsonNode patchedResource)
            throws JsonProcessingException {
        BytesReference patchedResourceAsByteReference = new BytesArray(
                DefaultObjectMapper.objectMapper.writeValueAsString(patchedResource).getBytes(StandardCharsets.UTF_8));
        return getValidator(request, patchedResourceAsByteReference);
    }

    // Prevent the case where action group references to itself in the allowed_actions.
    protected Boolean hasActionGroupSelfReference(SecurityDynamicConfiguration<?> mdc, String name) {
        List<String> allowedActions = ((ActionGroupsV7) mdc.getCEntry(name)).getAllowed_actions();
        return allowedActions.contains(name);
    }
}
