const { AnalyticsQueryBuilder } = require('@condo/domains/common/utils/serverSchema/AnalyticsQueryBuilder')
const { getSchemaCtx } = require('@core/keystone/schema')
const has = require('lodash/get')
const get = require('lodash/get')
const { TICKET_REPORT_DAY_GROUP_STEPS } = require('@condo/domains/ticket/constants/common')

const DATE_FORMATS = {
    day: 'DD.MM.YYYY',
    week: 'DD.MM.YYYY',
    month: 'MM.YYYY',
}

const sortStatusesByType = (statuses) => {
    // status priority map [min -> max]
    const orderedStatusPriority = ['closed', 'deferred', 'canceled', 'completed', 'processing', 'new_or_reopened']
    return statuses.sort((leftStatus, rightStatus) => {
        const leftStatusWeight = orderedStatusPriority.indexOf(leftStatus.type)
        const rightStatusWeight = orderedStatusPriority.indexOf(rightStatus.type)

        if (leftStatusWeight < rightStatusWeight) {
            return 1
        } else if (leftStatusWeight > rightStatusWeight) {
            return -1
        }
        return 0
    })
}

class TicketAnalyticsQueryBuilder extends AnalyticsQueryBuilder {
    aggregateBy = []
    constructor (where, groupBy) {
        super('Ticket', where, groupBy)
        this.aggregateBy = groupBy
            .some(e => TICKET_REPORT_DAY_GROUP_STEPS.includes(e)) ? ['dayGroup', ...this.groups] : [...this.groups]
    }

    async loadData () {
        this.result = null
        const { keystone } = await getSchemaCtx(this.domainName)
        const knex = keystone.adapter.knex

        const where = this.where.filter(condition => !this.isWhereInCondition(condition)).map(condition => {
            return Object.fromEntries(
                Object.entries(condition).map(([field, query]) => (
                    has(query, 'id') ? [field, query.id] : [field, query]
                ))
            )
        })

        // TODO(sitozzz): add support for n groups of id_in filter
        // create whereIn structure [['property_id', 'user_id'], [['some_property_id', 'some_user_id'], ...]]
        const whereIn = this.where.filter(this.isWhereInCondition).reduce((filter, currentFilter) => {
            const [groupName, groupCondition] = Object.entries(currentFilter)[0]
            const groupIdArray = get(groupCondition, 'id_in')
            const [filterEntities, filterValues] = filter
            filterEntities.push(groupName)
            filterValues.push(...groupIdArray.map(id => [id]))
            return filter
        }, [[], []])


        const query = knex(this.domainName)
            .count('id')
            .select(this.groups)
        if (this.aggregateBy.includes('dayGroup')) {
            query.select(knex.raw(`date_trunc('${this.dayGroup}',  "createdAt") as "dayGroup"`))
        }
        if (whereIn[0].length && whereIn[1].length) {
            this.result = await query.groupBy(this.aggregateBy)
                .where(where.reduce((acc, current) => ({ ...acc, ...current }), {}))
                .whereIn(whereIn[0], whereIn[1])
                .whereBetween('createdAt', [this.dateRange.from, this.dateRange.to])
        }
        this.result = await query.groupBy(this.aggregateBy)
            .where(where.reduce((acc, current) => ({ ...acc, ...current }), {}))
            .whereBetween('createdAt', [this.dateRange.from, this.dateRange.to])
    }
}

module.exports = {
    DATE_FORMATS,
    TicketAnalyticsQueryBuilder,
    sortStatusesByType,
}
