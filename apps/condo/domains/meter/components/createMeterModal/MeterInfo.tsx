import { Button, Col, Form, FormInstance, Input, Row, Select, Space, Typography } from 'antd'
import React, { useState } from 'react'
import { IMeterResourceUIState } from '../../utils/clientSchema/MeterResource'
import { useIntl } from '@core/next/intl'
import { ChevronIcon } from '@condo/domains/common/components/icons/ChevronIcon'
import { ELECTRICITY_METER_RESOURCE_ID } from '../../constants/constants'
import styled from '@emotion/styled'
import { useValidations } from '@condo/domains/common/hooks/useValidations'
import DatePicker from '@condo/domains/common/components/Pickers/DatePicker'
import { Rule } from 'rc-field-form/lib/interface'
import { useOrganization } from '@core/next/organization'
import { Meter } from '../../utils/clientSchema'
import { IMeterFormState } from '../../utils/clientSchema/Meter'

const { Option } = Select

const METER_INFO_INPUT_COL_SPAN = 11
const TARIFFS_NUMBER = 4

const getTariffNumberSelectOptions = () => {
    return Array.from({ length: TARIFFS_NUMBER }, (_, i) => i + 1)
        .map(number => (
            <Option key={number} value={number}>
                {number}
            </Option>
        ))
}

interface ICreateMeterModalDatePickerProps {
    label: string,
    name: string,
    rules?: Rule[],
    dependencies?: string[]
}

const CreateMeterModalDatePicker = ({ label, name, rules, dependencies }: ICreateMeterModalDatePickerProps) => {
    const intl = useIntl()
    const EnterDatePlaceHolder = intl.formatMessage({ id: 'EnterDate' })

    return (
        <Col span={METER_INFO_INPUT_COL_SPAN}>
            <Form.Item
                label={label}
                name={name}
                rules={rules}
                validateTrigger={['onBlur', 'onSubmit']}
                dependencies={dependencies}
            >
                <DatePicker
                    placeholder={EnterDatePlaceHolder}
                    format='DD.MM.YYYY'
                    style={{ width: '100%' }}
                />
            </Form.Item>
        </Col>
    )
}

type ChevronIconWrapperProps = {
    direction: 'down' | 'up',
}

const ChevronIconWrapper = styled.div<ChevronIconWrapperProps>`
    transform: rotate(${props => props.direction === 'down' ? 0 : 180}deg);
    display: flex;
`

type MeterInfoProps = {
    form: FormInstance,
    resource: IMeterResourceUIState
    newMeters: IMeterFormState[]
}

export const MeterInfo = ({ form, resource, newMeters }: MeterInfoProps) => {
    const intl = useIntl()
    const MeterNumberMessage = intl.formatMessage({ id: 'pages.condo.meter.MeterNumber' })
    const MeterPlaceMessage = intl.formatMessage({ id: 'pages.condo.meter.MeterPlace' })
    const MoreParametersMessage = intl.formatMessage({ id: 'MoreParameters' })
    const LessParametersMessage = intl.formatMessage({ id: 'LessParameters' })
    const TariffsCountMessage = intl.formatMessage({ id: 'pages.condo.meter.TariffsNumber' })
    const InstallationDateMessage = intl.formatMessage({ id: 'pages.condo.meter.InstallationDate' })
    const CommissioningDateMessage = intl.formatMessage({ id: 'pages.condo.meter.CommissioningDate' })
    const SealingDateMessage = intl.formatMessage({ id: 'pages.condo.meter.SealingDate' })
    const VerificationDateMessage = intl.formatMessage({ id: 'pages.condo.meter.VerificationDate' })
    const NextVerificationDateMessage = intl.formatMessage({ id: 'pages.condo.meter.NextVerificationDate' })
    const MeterWithSameNumberIsExistMessage = intl.formatMessage({ id: 'pages.condo.meter.MeterWithSameNumberIsExist' })
    const ControlReadingsDateMessage = intl.formatMessage({ id: 'pages.condo.meter.ControlReadingsDate' })
    const CanNotBeEarlierThanInstallationMessage = intl.formatMessage({ id: 'pages.condo.meter.СanNotBeEarlierThanInstallation' })
    const CanNotBeEarlierThanFirstVerificationMessage = intl.formatMessage({ id: 'pages.condo.meter.CanNotBeEarlierThanFirstVerification' })

    const { organization } = useOrganization()

    const { objs: metersWithSameNumber, refetch } = Meter.useObjects({
        where: {
            organization: null,
        },
    })

    const earlierThanInstallationValidator: Rule = {
        validator: async (_, value) => {
            if (!value || !form.getFieldValue('installationDate'))
                return Promise.resolve()

            const installationDate = form.getFieldValue('installationDate')
            if (value.toDate() < installationDate.toDate()) {
                return Promise.reject(CanNotBeEarlierThanInstallationMessage)
            }

            return Promise.resolve()
        },
    }

    const earlierThanFirstVerificationDateValidator: Rule = {
        validator: async (_, value) => {
            if (!value || !form.getFieldValue('verificationDate'))
                return Promise.resolve()

            const installationDate = form.getFieldValue('verificationDate')
            if (value.toDate() < installationDate.toDate()) {
                return Promise.reject(CanNotBeEarlierThanFirstVerificationMessage)
            }

            return Promise.resolve()
        },
    }

    const meterWithSameNumberValidator: Rule = {
        validator: async (_, value) => {
            await refetch({
                where: {
                    organization: { id: organization && organization.id },
                    number: value,
                },
            })

            if (metersWithSameNumber.length > 0 || (newMeters && newMeters.find(newMeter => newMeter.number === value)))
                return Promise.reject(MeterWithSameNumberIsExistMessage)
            return Promise.resolve()
        },
    }

    const { requiredValidator } = useValidations()

    const validations = {
        number: [requiredValidator, meterWithSameNumberValidator],
        numberOfTariffs: [requiredValidator],
        commissioningDate: [earlierThanInstallationValidator],
        sealingDate: [earlierThanInstallationValidator],
        verificationDate: [earlierThanInstallationValidator],
        nextVerificationDate: [earlierThanInstallationValidator, earlierThanFirstVerificationDateValidator],
        controlReadingsDate: [earlierThanInstallationValidator],
    }

    const [isAdditionalFieldsCollapsed, setIsAdditionalFieldsCollapsed] = useState<boolean>(true)

    const isElectricityMeter = resource.id === ELECTRICITY_METER_RESOURCE_ID

    return (
        <Row gutter={[0, 20]}>
            <Col span={24}>
                <Row justify={'space-between'} gutter={[0, 20]}>
                    <Col span={METER_INFO_INPUT_COL_SPAN}>
                        <Form.Item
                            label={MeterNumberMessage}
                            name='number'
                            rules={validations.number}
                            validateTrigger={['onBlur', 'onSubmit']}
                        >
                            <Input />
                        </Form.Item>
                    </Col>
                    <Col span={METER_INFO_INPUT_COL_SPAN}>
                        <Form.Item
                            label={MeterPlaceMessage}
                            name='place'
                        >
                            <Input />
                        </Form.Item>
                    </Col>
                    {
                        isElectricityMeter ? (
                            <Col span={METER_INFO_INPUT_COL_SPAN}>
                                <Form.Item
                                    rules={validations.numberOfTariffs}
                                    hidden={!isElectricityMeter}
                                    label={TariffsCountMessage}
                                    name='numberOfTariffs'
                                >
                                    <Select>
                                        {getTariffNumberSelectOptions()}
                                    </Select>
                                </Form.Item>
                            </Col>
                        ) : null
                    }
                    {
                        !isAdditionalFieldsCollapsed ? (
                            <>
                                <CreateMeterModalDatePicker
                                    label={InstallationDateMessage}
                                    name='installationDate'
                                />
                                <CreateMeterModalDatePicker
                                    label={CommissioningDateMessage}
                                    name='commissioningDate'
                                    rules={validations.commissioningDate}
                                    dependencies={['installationDate']}
                                />
                                <CreateMeterModalDatePicker
                                    label={SealingDateMessage}
                                    name='sealingDate'
                                    rules={validations.sealingDate}
                                    dependencies={['installationDate']}
                                />
                                <CreateMeterModalDatePicker
                                    label={VerificationDateMessage}
                                    name='verificationDate'
                                    rules={validations.verificationDate}
                                    dependencies={['installationDate']}
                                />
                                <CreateMeterModalDatePicker
                                    label={NextVerificationDateMessage}
                                    name='nextVerificationDate'
                                    rules={validations.nextVerificationDate}
                                    dependencies={['installationDate', 'verificationDate']}
                                />
                                <CreateMeterModalDatePicker
                                    label={ControlReadingsDateMessage}
                                    name='controlReadingsDate'
                                    rules={validations.controlReadingsDate}
                                    dependencies={['installationDate']}
                                />
                            </>
                        ) : null
                    }
                </Row>
            </Col>
            <Col>
                <Button
                    type="text"
                    onClick={() => { setIsAdditionalFieldsCollapsed(prevState => !prevState) }}
                    style={{
                        padding: 0,
                    }}
                >
                    <Typography.Text type={'success'} strong>
                        <Space direction={'horizontal'} align={'center'}>
                            {isAdditionalFieldsCollapsed ? MoreParametersMessage : LessParametersMessage}
                            <ChevronIconWrapper direction={isAdditionalFieldsCollapsed ? 'down' : 'up'}>
                                <ChevronIcon />
                            </ChevronIconWrapper>
                        </Space>
                    </Typography.Text>
                </Button>
            </Col>
        </Row>
    )
}