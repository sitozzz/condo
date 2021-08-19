/**
 * Generated by `createschema ticket.Ticket organization:Text; statusReopenedCounter:Integer; statusReason?:Text; status:Relationship:TicketStatus:PROTECT; number?:Integer; client?:Relationship:User:SET_NULL; clientName:Text; clientEmail:Text; clientPhone:Text; operator:Relationship:User:SET_NULL; assignee?:Relationship:User:SET_NULL; classifier:Relationship:TicketClassifier:PROTECT; details:Text; meta?:Json;`
 * In most cases you should not change it by hands
 * Please, don't remove `AUTOGENERATE MARKER`s
 */
const { generateGqlQueries } = require('@condo/domains/common/utils/codegeneration/generate.gql')
const { gql } = require('graphql-tag')
const COMMON_FIELDS = 'id dv sender v deletedAt newId createdBy { id name } updatedBy { id name } createdAt updatedAt'

const THREE_LVL_CLASSIFIER_FIELDS = 'placeClassifier { id name } categoryClassifier { id name } problemClassifier { id name } classifierRule { id }'
const TICKET_FIELDS = `{ organization { id name } property { id name address } unitName sectionName floorName status { id name type organization { id } colors } statusReopenedCounter statusUpdatedAt statusReason number client { id name } clientName clientEmail clientPhone contact { id name } operator { id name } assignee { id name } executor { id name } watchers { id name } classifier { id name } ${THREE_LVL_CLASSIFIER_FIELDS} details related { id details } isEmergency isPaid meta source { id name type } sourceMeta ${COMMON_FIELDS} }`
const Ticket = generateGqlQueries('Ticket', TICKET_FIELDS)

// TODO (sitozzz): @pahaz, @Dimitreee is it legal to do like this?
const ANALITYCS_TICKET_FIELDS = '{ id createdAt property { id } status { id type } assignee { id } executor { id } }'
const AnaliticsTicket = generateGqlQueries('Ticket', ANALITYCS_TICKET_FIELDS)
const TICKET_STATUS_FIELDS = `{ organization { id } type name colors ${COMMON_FIELDS} }`
const TicketStatus = generateGqlQueries('TicketStatus', TICKET_STATUS_FIELDS)
const TICKET_SOURCE_FIELDS = `{ organization { id } type name ${COMMON_FIELDS} }`
const TicketSource = generateGqlQueries('TicketSource', TICKET_SOURCE_FIELDS)
const TICKET_CLASSIFIER_FIELDS = `{ organization { id } parent { id name parent { id name } } fullName name ${COMMON_FIELDS} }`
const TicketClassifier = generateGqlQueries('TicketClassifier', TICKET_CLASSIFIER_FIELDS)
const SHARE_TICKET_MUTATION = gql`
    mutation shareTicket($data: ShareTicketInput!) {
        obj: shareTicket(data: $data) { status }
    }
`
/*
    We cannot use generated fields from TicketChange here, because we will have circular dependency,
    by requiring something from ./schema modules, that will cause all required items to be undefined.
    So, do it by hands here.
    PS: not exactly by hands, pasted from debugger ;)
*/
const TICKET_CHANGE_DATA_FIELDS = [
    'statusReopenedCounterFrom',
    'statusReopenedCounterTo',
    'statusReasonFrom',
    'statusReasonTo',
    'numberFrom',
    'numberTo',
    'clientNameFrom',
    'clientNameTo',
    'clientEmailFrom',
    'clientEmailTo',
    'clientPhoneFrom',
    'clientPhoneTo',
    'detailsFrom',
    'detailsTo',
    'isPaidFrom',
    'isPaidTo',
    'isEmergencyFrom',
    'isEmergencyTo',
    'metaFrom',
    'metaTo',
    'sectionNameFrom',
    'sectionNameTo',
    'floorNameFrom',
    'floorNameTo',
    'unitNameFrom',
    'unitNameTo',
    'sourceMetaFrom',
    'sourceMetaTo',
    'organizationIdFrom',
    'organizationIdTo',
    'organizationDisplayNameFrom',
    'organizationDisplayNameTo',
    'statusIdFrom',
    'statusIdTo',
    'statusDisplayNameFrom',
    'statusDisplayNameTo',
    'clientIdFrom',
    'clientIdTo',
    'clientDisplayNameFrom',
    'clientDisplayNameTo',
    'contactIdFrom',
    'contactIdTo',
    'contactDisplayNameFrom',
    'contactDisplayNameTo',
    'operatorIdFrom',
    'operatorIdTo',
    'operatorDisplayNameFrom',
    'operatorDisplayNameTo',
    'assigneeIdFrom',
    'assigneeIdTo',
    'assigneeDisplayNameFrom',
    'assigneeDisplayNameTo',
    'executorIdFrom',
    'executorIdTo',
    'executorDisplayNameFrom',
    'executorDisplayNameTo',
    'classifierIdFrom',
    'classifierIdTo',
    'classifierDisplayNameFrom',
    'classifierDisplayNameTo',
    'placeClassifierIdFrom',
    'placeClassifierIdTo',
    'placeClassifierDisplayNameFrom',
    'placeClassifierDisplayNameTo',
    'categoryClassifierIdFrom',
    'categoryClassifierIdTo',
    'categoryClassifierDisplayNameFrom',
    'categoryClassifierDisplayNameTo',
    'problemClassifierIdFrom',
    'problemClassifierIdTo',
    'problemClassifierDisplayNameFrom',
    'problemClassifierDisplayNameTo',
    'relatedIdFrom',
    'relatedIdTo',
    'relatedDisplayNameFrom',
    'relatedDisplayNameTo',
    'propertyIdFrom',
    'propertyIdTo',
    'propertyDisplayNameFrom',
    'propertyDisplayNameTo',
    'sourceIdFrom',
    'sourceIdTo',
    'sourceDisplayNameFrom',
    'sourceDisplayNameTo',
    'watchersIdsFrom',
    'watchersIdsTo',
    'watchersDisplayNamesFrom',
    'watchersDisplayNamesTo',
]
const TICKET_CHANGE_FIELDS = `{ ticket { id property { address } } id dv sender v createdBy { id name } updatedBy { id name } createdAt updatedAt ${TICKET_CHANGE_DATA_FIELDS.join(' ')} }`
const TicketChange = generateGqlQueries('TicketChange', TICKET_CHANGE_FIELDS)
const TICKET_FILE_FIELDS = `{ id file { id originalFilename publicUrl mimetype } organization { id } ticket { id } ${COMMON_FIELDS} }`
const TicketFile = generateGqlQueries('TicketFile', TICKET_FILE_FIELDS)
const TICKET_COMMENT_FIELDS = `{ ticket { id } user { id name } content ${COMMON_FIELDS} }`
const TicketComment = generateGqlQueries('TicketComment', TICKET_COMMENT_FIELDS)
const TICKET_ANALYTICS_REPORT_QUERY = gql`
    query ticketAnalyticsReport ($data: TicketAnalyticsReportInput!) {
        result: ticketAnalyticsReport(data: $data) { result { count status property dayGroup } }
    }
`
const EXPORT_TICKET_ANALYTICS_TO_EXCEL = gql`
    query exportTicketAnalyticsToExcel ($data: TicketAnalyticsReportInput!) {
        result: exportTicketAnalyticsToExcel(data: $data) { link }
    }
`

const RESIDENT_TICKET_FIELDS = `{ organization { id name } property { id name address } unitName sectionName floorName number client { id name } clientName clientEmail clientPhone status { id name type organization { id } colors } classifier { id name } ${THREE_LVL_CLASSIFIER_FIELDS} details related { id details } isEmergency isPaid source { id name type } id dv sender v deletedAt newId createdAt updatedAt }`
const ResidentTicket = generateGqlQueries('ResidentTicket', RESIDENT_TICKET_FIELDS)

const TICKET_PLACE_CLASSIFIER_FIELDS = `{ organization { id } name ${COMMON_FIELDS} }`
const TicketPlaceClassifier = generateGqlQueries('TicketPlaceClassifier', TICKET_PLACE_CLASSIFIER_FIELDS)

const TICKET_CATEGORY_CLASSIFIER_FIELDS = `{ organization { id } name ${COMMON_FIELDS} }`
const TicketCategoryClassifier = generateGqlQueries('TicketCategoryClassifier', TICKET_CATEGORY_CLASSIFIER_FIELDS)

const TICKET_PROBLEM_CLASSIFIER_FIELDS = `{ organization { id } name ${COMMON_FIELDS} }`
const TicketProblemClassifier = generateGqlQueries('TicketProblemClassifier', TICKET_PROBLEM_CLASSIFIER_FIELDS)

const TICKET_CLASSIFIER_RULE_FIELDS = `{ place { id name } category { id name } problem { id name } ${COMMON_FIELDS} }`
const TicketClassifierRule = generateGqlQueries('TicketClassifierRule', TICKET_CLASSIFIER_RULE_FIELDS)

/* AUTOGENERATE MARKER <CONST> */
const EXPORT_TICKETS_TO_EXCEL =  gql`
    query exportTicketsToExcel ($data: ExportTicketsToExcelInput!) {
        result: exportTicketsToExcel(data: $data) { status, linkToFile }
    }
`
const GET_TICKET_WIDGET_REPORT_DATA = gql`
    query getWidgetData ($data: TicketReportWidgetInput!) {
        result: ticketReportWidgetData(data: $data) { data { statusName, currentValue, growth, statusType } }
    }
`
module.exports = {
    Ticket,
    AnaliticsTicket,
    TicketStatus,
    TicketChange,
    TicketSource,
    ResidentTicket,
    TicketClassifier,
    TicketFile,
    TICKET_CHANGE_DATA_FIELDS,
    EXPORT_TICKETS_TO_EXCEL,
    GET_TICKET_WIDGET_REPORT_DATA,
    TicketComment,
    TICKET_ANALYTICS_REPORT_QUERY,
    SHARE_TICKET_MUTATION,
    TicketPlaceClassifier,
    TicketCategoryClassifier,
    TicketProblemClassifier,
    TicketClassifierRule,
    RESIDENT_TICKET_FIELDS,
    EXPORT_TICKET_ANALYTICS_TO_EXCEL,
/* AUTOGENERATE MARKER <EXPORTS> */
}
