import React, { useState, useCallback } from 'react'
import { Col, Row } from 'antd'
import { useRouter } from 'next/router'
import cloneDeep from 'lodash/cloneDeep'
import get from 'lodash/get'
import isEmpty from 'lodash/isEmpty'
import {
    EmptyBuildingBlock,
    EmptyFloor,
    BuildingAxisY,
    BuildingChooseSections,
    MapSectionContainer,
} from './BuildingPanelCommon'
import { UnitButton } from '@condo/domains/property/components/panels/Builder/UnitButton'
import { MapView } from './MapConstructor'
import { BuildingMap } from '@app/condo/schema'
import { useObject } from '@condo/domains/property/utils/clientSchema/Property'
import ScrollContainer from 'react-indiana-drag-scroll'
import { FullscreenWrapper, FullscreenHeader } from './Fullscreen'
import { AddressTopTextContainer } from './BuildingPanelEdit'

interface IBuildingPanelViewProps {
    map: BuildingMap
}

export const BuildingPanelView: React.FC<IBuildingPanelViewProps> = ({ map }) => {
    const mapView = new MapView(map)
    const [Map, setMap] = useState(mapView)
    // TODO(zuch): Ask for a better solution
    const refresh = () => setMap(cloneDeep(Map))
    return (
        <PropertyMapView builder={Map} refresh={refresh} />
    )
}

interface IPropertyMapViewProps {
    builder: MapView
    refresh(): void
}

const CHESS_ROW_STYLE: React.CSSProperties = {
    width: '100%',
    height: '100%',
    textAlign: 'center',
}
const CHESS_COL_STYLE: React.CSSProperties = {
    paddingTop: '60px',
    paddingBottom: '60px',
}
const CHESS_SCROLL_HOLDER_STYLE: React.CSSProperties = {
    whiteSpace: 'nowrap',
    position: 'static',
    paddingTop: '20px',
}
const CHESS_SCROLL_CONTAINER_STYLE: React.CSSProperties = {
    paddingBottom: '20px',
    width: '100%',
    overflowY: 'hidden',
}
const UNIT_BUTTON_SECTION_STYLE: React.CSSProperties = { width: '100%', marginTop: '8px' }
const FLOOR_CONTAINER_STYLE: React.CSSProperties = { display: 'block' }

export const PropertyMapView: React.FC<IPropertyMapViewProps> = ({ builder, refresh }) => {
    const { query: { id } } = useRouter()
    const { obj: property } = useObject({ where: { id: id as string } })

    const [isFullscreen, setFullscreen] = useState(false)

    const toggleFullscreen = useCallback(() => {
        setFullscreen(!isFullscreen)
    }, [isFullscreen])

    return (
        <FullscreenWrapper mode={'view'} className={isFullscreen ? 'fullscreen' : '' }>
            <FullscreenHeader edit={false}>
                <Row>
                    <Col flex={0}>
                        <AddressTopTextContainer>{get(property, 'address')}</AddressTopTextContainer>
                    </Col>
                </Row>
            </FullscreenHeader>
            <Row align='middle' style={CHESS_ROW_STYLE}>
                {
                    builder.isEmpty ?
                        <Col span={24} style={CHESS_COL_STYLE}>
                            <EmptyBuildingBlock />
                        </Col>
                        :
                        <Col span={24} style={CHESS_SCROLL_HOLDER_STYLE}>
                            <ScrollContainer
                                className="scroll-container"
                                style={CHESS_SCROLL_CONTAINER_STYLE}
                                vertical={false}
                                horizontal={true}
                                hideScrollbars={false}
                                nativeMobileScroll={true}
                            >
                                {
                                    !isEmpty(builder.sections) && (
                                        <BuildingAxisY floors={builder.possibleChosenFloors} />
                                    )
                                }
                                {
                                    builder.sections.map(section => (
                                        <MapSectionContainer
                                            key={section.id}
                                            visible={builder.isSectionVisible(section.id)}
                                        >
                                            {
                                                builder.possibleChosenFloors.map(floorIndex => {
                                                    const floorInfo = section.floors.find(floor => floor.index === floorIndex)
                                                    if (floorInfo && floorInfo.units.length) {
                                                        return (
                                                            <div key={floorInfo.id} style={FLOOR_CONTAINER_STYLE}>
                                                                {
                                                                    floorInfo.units.map(unit => {
                                                                        return (
                                                                            <UnitButton
                                                                                key={unit.id}
                                                                                noninteractive
                                                                            >{unit.label}</UnitButton>
                                                                        )
                                                                    })
                                                                }
                                                            </div>
                                                        )
                                                    } else {
                                                        return (
                                                            <EmptyFloor key={`empty_${section.id}_${floorIndex}`} />
                                                        )
                                                    }
                                                })
                                            }
                                            <UnitButton
                                                secondary
                                                style={UNIT_BUTTON_SECTION_STYLE}
                                                disabled
                                            >{section.name}</UnitButton>
                                        </MapSectionContainer>
                                    ))
                                }
                            </ScrollContainer>
                            {
                                <BuildingChooseSections
                                    builder={builder}
                                    refresh={refresh}
                                    toggleFullscreen={toggleFullscreen}
                                    isFullscreen={isFullscreen}
                                    mode="view"
                                />
                            }
                        </Col>
                }
            </Row>
        </FullscreenWrapper>
    )
}
