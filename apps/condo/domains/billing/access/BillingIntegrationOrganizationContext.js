/**
 * Generated by `createschema billing.BillingIntegrationOrganizationContext 'integration:Relationship:BillingIntegration:PROTECT; organization:Relationship:Organization:CASCADE; settings:Json; state:Json' --force`
 */

const { get } = require('lodash')
const { getById } = require('@core/keystone/schema')
const { checkOrganizationPermission, checkBillingIntegrationAccessRight } = require('@condo/domains/organization/utils/accessSchema')

async function canReadBillingIntegrationOrganizationContexts ({ authentication: { item: user } }) {
    if (!user) return false
    if (user.isAdmin) return true
    return {
        // TODO(pahaz & toplenboren): add an ability to create integration context from interface
        OR: [
            { organization: { employees_some: { user: { id: user.id }, role: { canManageIntegrations: true }, deletedAt: null } } },
            { integration: { accessRights_some: { user: { id: user.id } } } },
        ],
    }
}

async function canManageBillingIntegrationOrganizationContexts ({ authentication: { item: user }, originalInput, operation, itemId }) {
    if (!user) return false
    if (user.isAdmin) return true
    let organizationId
    let integrationId
    if (operation === 'create') {
        // NOTE: can only be created by the organization integration manager
        organizationId = get(originalInput, ['organization', 'connect', 'id'])
        integrationId = get(originalInput, ['integration', 'connect', 'id'])
        if (!organizationId || !integrationId) return false
    } else if (operation === 'update') {
        // NOTE: can update by the organization integration manager OR the integration account
        if (!itemId) return false
        const context = await getById('BillingIntegrationOrganizationContext', itemId)
        if (!context) return false
        const { organization, integration } = context
        organizationId = organization
        integrationId = integration
    }
    const canManageIntegrations = await checkOrganizationPermission(user.id, organizationId, 'canManageIntegrations')
    if (canManageIntegrations) return true
    return await checkBillingIntegrationAccessRight(user.id, integrationId)
}

/*
  Rules are logical functions that used for list access, and may return a boolean (meaning
  all or no items are available) or a set of filters that limit the available items.
*/
module.exports = {
    canReadBillingIntegrationOrganizationContexts,
    canManageBillingIntegrationOrganizationContexts,
}
