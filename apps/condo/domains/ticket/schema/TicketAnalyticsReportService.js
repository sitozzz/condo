/**
 * Generated by `createservice ticket.TicketAnalyticsReportService`
 */

const { GQLCustomSchema, getByCondition } = require('@core/keystone/schema')
const access = require('@condo/domains/ticket/access/TicketAnalyticsReportService')
const moment = require('moment')
const { sortStatusesByType } = require('@condo/domains/ticket/utils/serverSchema/analytics.helper')
const { TicketAnalyticsQueryBuilder } = require('@condo/domains/ticket/utils/serverSchema/analytics.helper')
const { DATE_DISPLAY_FORMAT, TICKET_REPORT_DAY_GROUP_STEPS } = require('@condo/domains/ticket/constants/common')
const { Property: PropertyServerUtils } = require('@condo/domains/property/utils/serverSchema')
const { TicketStatus: TicketStatusServerUtils, Ticket } = require('@condo/domains/ticket/utils/serverSchema')
const isEmpty = require('lodash/isEmpty')
const get = require('lodash/get')
const groupObjectBy = require('lodash/groupBy')
const { createExportFile } = require('@condo/domains/common/utils/createExportFile')

const createPropertyRange = async (context, organizationWhereInput) => {
    const properties = await PropertyServerUtils.getAll(context, { organization:  organizationWhereInput  })
    return properties.map( property => ({ label: property.address, value: property.id }))
}

const createStatusRange = async (context, organizationWhereInput, labelKey = 'name') => {
    const statuses = await TicketStatusServerUtils.getAll(context, { OR: [
        { organization: organizationWhereInput },
        { organization_is_null: true },
    ] })
    // We use organization specific statuses if they exists
    // or default if there is no organization specific status with a same type
    const allStatuses = statuses.filter(status => {
        if (!status.organization) {
            return true
        }
        return !statuses
            .find(organizationStatus => organizationStatus.organization !== null && organizationStatus.type === status.type)
    })
    return sortStatusesByType(allStatuses).map(status => ({ label: status[labelKey], value: status.id }))
}

const getTicketCounts = async (context, where, groupBy, extraLabels = {}) => {
    const analyticsQueryBuilder = new TicketAnalyticsQueryBuilder(where, groupBy)
    await analyticsQueryBuilder.loadData()

    const translates = {}
    for (const group of groupBy) {
        switch (group) {
            case 'property':
                translates[group] = await createPropertyRange(context, where.organization)
                break
            case 'status':
                translates[group] = await createStatusRange(
                    context, where.organization, isEmpty(extraLabels) ? 'name' :  extraLabels[group]
                )
                break
            default:
                break
        }
    }
    return  analyticsQueryBuilder
        .getResult(({ count, dayGroup, ...searchResult }) =>
        {
            if (!isEmpty(translates)) {
                Object.entries(searchResult).forEach(([groupName, value]) => {
                    const translateMapping = get(translates, groupName, false)
                    if (translateMapping) {
                        const translation = translateMapping.find(translate => translate.value === value)
                        searchResult[groupName] = translation.label
                    }
                })
                return {
                    ...searchResult,
                    dayGroup: moment(dayGroup).format(DATE_DISPLAY_FORMAT),
                    count: parseInt(count),
                }
            }
            return {
                ...searchResult,
                dayGroup: moment(dayGroup).format(DATE_DISPLAY_FORMAT),
                count:parseInt(count),
            }
        })
}

const aggregateData = (data, groupByFilter) => {
    const [axisGroupKey] = groupByFilter
    const labelsGroupKey = TICKET_REPORT_DAY_GROUP_STEPS.includes(groupByFilter[1]) ? 'dayGroup' : groupByFilter[1]
    const groupedResult = groupObjectBy(data, axisGroupKey)
    const result = {}
    Object.entries(groupedResult).forEach(([filter, dataObject]) => {
        result[filter] = Object.fromEntries(
            Object.entries(
                groupObjectBy(dataObject, labelsGroupKey)
            ).map(([labelsGroupTitle, resultObject]) => [labelsGroupTitle, resultObject[0].count])
        )
    })
    return { result, groupKeys: [axisGroupKey, labelsGroupKey] }
}

const ticketAnalyticsExcelExportDataMapper = (data, where = {}, groupBy = [], translates = {}) => {
    const uniqueDates = Array.from(new Set(Object.values(data).flatMap(e => Object.keys(e))))
    const result = []
    const address = get(translates, 'property')

    uniqueDates.forEach((date, key) => {
        const restTableColumns = {}
        Object.keys(data).forEach(ticketType => {
            restTableColumns[ticketType] = data[ticketType][date]
        })
        result.push({ key, address, date, ...restTableColumns })
    })
    return result
}

const TicketAnalyticsReportService = new GQLCustomSchema('TicketAnalyticsReportService', {
    types: [
        {
            access: true,
            type: 'enum TicketAnalyticsGroupBy { day week month status property }',
        },
        {
            access: true,
            type: 'input TicketAnalyticsReportInput { where: TicketWhereInput!, groupBy: [TicketAnalyticsGroupBy!] }',
        },
        {
            access: true,
            type: 'type TicketAnalyticsReportOutput { result: [TicketGroupedCounter!] }',
        },
        {
            access: true,
            type: 'type TicketGroupedCounter { count: Int!, status: String, property: String, dayGroup: String! }',
        },
        {
            access: true,
            type: 'input ExportTicketAnalyticsToExcelInput { where: TicketWhereInput!, groupBy: [TicketAnalyticsGroupBy!], translates: JSON }',
        },
        {
            access: true,
            type: 'type ExportTicketAnalyticsToExcelOutput { link: String! }',
        },
    ],
    queries: [
        {
            access: access.canReadTicketAnalyticsReport,
            schema: 'ticketAnalyticsReport(data: TicketAnalyticsReportInput): TicketAnalyticsReportOutput',
            resolver: async (parent, args, context, info, extra = {}) => {
                const { data: { where = {}, groupBy = [] } } = args
                const result = await getTicketCounts(context, where, groupBy)
                return { result }
            },
        },
        {
            access: access.canReadTicketAnalyticsReport,
            schema: 'exportTicketAnalyticsToExcel(data: ExportTicketAnalyticsToExcelInput): ExportTicketAnalyticsToExcelOutput',
            resolver: async (parent, args, context, info, extra = {}) => {
                const { data: { where = {}, groupBy = [], translates = {} } } = args
                const ticketCounts = await getTicketCounts(context, where, groupBy, { status: 'type' })
                const { result, groupKeys } = aggregateData(ticketCounts, groupBy)
                const ticketAccessCheck = await Ticket.getAll(context, where, { first: 1 })
                const [groupBy1, groupBy2] = groupKeys
                const excelRows = ticketAnalyticsExcelExportDataMapper(result, where, groupBy, translates)
                const organization = await getByCondition('Organization', {
                    id: where.organization.id,
                })
                const link = await createExportFile({
                    fileName: `ticket_analytics_${moment().format('DD_MM')}.xlsx`,
                    templatePath: `./domains/ticket/templates/${organization.country}/TicketAnalyticsExportTemplate[${groupBy1}_${groupBy2}].xlsx`,
                    replaces: { tickets: excelRows },
                    meta: {
                        listkey: 'Ticket',
                        id: ticketAccessCheck[0].id,
                    },
                })
                return { link }
            },
        },
    ],
})

module.exports = {
    TicketAnalyticsReportService,
}
