/**
 * Generated by `createschema organization.Organization 'country:Select:ru,en; name:Text; description?:Text; avatar?:File; meta:Json; employees:Relationship:OrganizationEmployee:CASCADE; statusTransitions:Json; defaultEmployeeRoleStatusTransitions:Json' --force`
 */
const { throwAuthenticationError } = require('@condo/domains/common/utils/apolloErrorFormatter')
const { RESIDENT } = require('@condo/domains/user/constants/common')
const { queryOrganizationEmployeeFromRelatedOrganizationFor, queryOrganizationEmployeeFor } = require('../utils/accessSchema')
const { Resident: ResidentServerUtils } = require('@condo/domains/resident/utils/serverSchema')
const { AcquiringIntegrationAccessRight } = require('@condo/domains/acquiring/utils/serverSchema')
const { get, uniq, compact } = require('lodash')
const access = require('@core/keystone/access')

async function canReadOrganizations ({ authentication: { item: user }, context }) {
    if (!user) return throwAuthenticationError()
    if (user.isAdmin || user.isSupport) return {}
    const userId = user.id
    if (user.type === RESIDENT) {
        const residents = await ResidentServerUtils.getAll(context, { user: { id: userId } })
        if (residents.length === 0) {
            return false
        }
        const organizations = compact(residents.map(resident => get(resident, ['organization', 'id'])))
        if (organizations.length > 0) {
            return {
                id_in: uniq(organizations),
            }
        }
        return false
    }

    const acquiringIntegrationRights = await AcquiringIntegrationAccessRight.getAll(context, {
        user: { id: userId, deletedAt: null },
    })

    // Acquiring integration can have access to organizations created by it
    // TODO (savelevMatthew): Better way to get access for acquiring integrations?
    if (acquiringIntegrationRights && acquiringIntegrationRights.length) {
        return {
            createdBy: { id: userId },
        }
    }

    return {
        OR: [
            queryOrganizationEmployeeFor(userId),
            queryOrganizationEmployeeFromRelatedOrganizationFor(userId),
        ],
    }
}

async function canManageOrganizations ({ authentication: { item: user }, operation }) {
    if (!user) return throwAuthenticationError()
    if (user.isAdmin) return true
    if (operation === 'create') {
        return false
    } else if (operation === 'update') {
        // user is inside employee list and is not blocked
        return {
            employees_some: { user: { id: user.id }, role: { canManageOrganization: true }, isBlocked: false, deletedAt: null },
        }
    }
    return false
}

const canAccessToImportField = {
    read: access.userIsNotResidentUser,
    create: access.userIsAdmin,
    update: access.userIsAdmin,
}
/*
  Rules are logical functions that used for list access, and may return a boolean (meaning
  all or no items are available) or a set of filters that limit the available items.
*/
module.exports = {
    canReadOrganizations,
    canManageOrganizations,
    canAccessToImportField,
}
