import CustomLink from '../components/CustomLink'

function HomePage () {
    return (
        <div>
            <div>Добро пожаловать!</div>
            <CustomLink path="/tests/disc">
                Пройти первый тест
            </CustomLink>
        </div>
    )
}

export default HomePage
