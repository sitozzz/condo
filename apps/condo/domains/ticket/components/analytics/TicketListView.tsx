import React from 'react'
import { useIntl } from '@core/next/intl'
import { Skeleton, Table, TableColumnsType } from 'antd'
import { ticketAnalyticsPageFilters } from '@condo/domains/ticket/utils/helpers'
import { ITicketAnalyticsPageWidgetProps } from './TicketChartView'

interface ITicketAnalyticsPageListViewProps extends ITicketAnalyticsPageWidgetProps {
    filters: null | ticketAnalyticsPageFilters
}

const TicketListView: React.FC<ITicketAnalyticsPageListViewProps> = ({
    loading = false,
    data,
    viewMode,
    mapperInstance,
    filters }) => {
    const intl = useIntl()
    const DateTitle = intl.formatMessage({ id: 'Date' })
    const AddressTitle = intl.formatMessage({ id: 'field.Address' })
    const AllAddressTitle = intl.formatMessage({ id: 'pages.condo.analytics.TicketAnalyticsPage.tableColumns.AllAddresses' })
    if (data === null || filters === null) {
        return <Skeleton loading={loading} active paragraph={{ rows: 10 }} />
    }
    const restOptions = {
        translations: {
            date: DateTitle,
            address: AddressTitle,
            allAddresses: AllAddressTitle,
        },
        filters: {
            addresses: filters.addressList.map(({ value }) => value),
        },
    }
    const { tableColumns, dataSource } = mapperInstance.getTableConfig(viewMode, data, restOptions)
    return (
        <Table
            bordered
            tableLayout={'fixed'}
            scroll={{ scrollToFirstRowOnChange: false }}
            loading={loading}
            dataSource={dataSource}
            columns={tableColumns as TableColumnsType}
            pagination={false}
        />
    )
}

export default TicketListView