import styled from '@emotion/styled'
import { Typography } from 'antd'
import classnames from 'classnames'
import Link from 'next/link'
import { useRouter } from 'next/router'
import React  from 'react'
import { useIntl } from '@core/next/intl'
import { colors } from '../constants/style'

const IconWrapper = styled.div``

const MenuItemWrapper = styled.span`
  cursor: pointer;
  padding: 16px 0;
  display: flex;
  border-radius: 8px;
  flex-direction: row;
  align-items: center;
  justify-content: flex-start;
  vertical-align: center;

  .label {
    font-size: 16px;
    transition: all 0.3s;
  }

  .icon {
    color: ${colors.lightGrey[5]};
    font-size: 20px;
    margin-right: 20px;
    transition: all 0.3s;
  }

  &:hover {
    .icon {
      color: ${colors.black};
    }
  }

  &.active {
    .label {
      font-weight: 700;
    }

    .icon {
      color: ${colors.black};
    }
  }
`

interface IMenuItemProps {
    path: string
    icon: React.ElementType
    label: string
    hideInMenu?: boolean
}

export const MenuItem: React.FC<IMenuItemProps> = (props) => {
    const { path, icon: Icon, label, hideInMenu } = props
    const { route } = useRouter()
    const intl = useIntl()

    if (hideInMenu) {
        return null
    }

    const menuItemClassNames = classnames({
        'active': path === '/' ? route === path : route.includes(path),
    })

    return (
        <Link href={path}>
            <MenuItemWrapper className={menuItemClassNames}>
                <IconWrapper className='icon'>
                    <Icon/>
                </IconWrapper>
                <Typography.Text className='label'>
                    {intl.formatMessage({ id: label })}
                </Typography.Text>
            </MenuItemWrapper>
        </Link>
    )
}