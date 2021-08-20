/**
 * Generated by `createschema division.Division 'name:Text; organization:Relationship:Organization:CASCADE; responsible:Relationship:OrganizationEmployee:PROTECT;'`
 * In most cases you should not change it by hands
 * Please, don't remove `AUTOGENERATE MARKER`s
 */

const { generateGqlQueries } = require('@condo/domains/common/utils/codegeneration/generate.gql')

const gql = require('graphql-tag')

const COMMON_FIELDS = 'id dv sender { dv fingerprint } v deletedAt newId createdBy { id name } updatedBy { id name } createdAt updatedAt'

const DIVISION_FIELDS = `{ name organization { id } responsible { id name } properties { id name address } executors { id name } ${COMMON_FIELDS} }`
const Division = generateGqlQueries('Division', DIVISION_FIELDS)

/* AUTOGENERATE MARKER <CONST> */

module.exports = {
    Division,
/* AUTOGENERATE MARKER <EXPORTS> */
}
