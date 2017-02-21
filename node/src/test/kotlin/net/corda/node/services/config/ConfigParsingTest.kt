package net.corda.node.services.config

import com.google.common.net.HostAndPort
import com.typesafe.config.Config
import com.typesafe.config.ConfigFactory.empty
import com.typesafe.config.ConfigRenderOptions.defaults
import com.typesafe.config.ConfigValueFactory
import net.corda.core.div
import org.assertj.core.api.Assertions.assertThat
import org.junit.Test
import java.net.URL
import java.nio.file.Path
import java.nio.file.Paths
import java.time.Instant
import java.time.LocalDate
import java.util.*
import kotlin.reflect.primaryConstructor

class ConfigParsingTest {
    @Test
    fun `String`() {
        val config = config("value" to "hello world!")
        val data = StringData("hello world!")
        assertThat(config.parseAs<StringData>()).isEqualTo(data)
        assertThat(data.toConfig()).isEqualTo(config)
    }

    @Test
    fun `List of String`() {
        testValueList<StringListData>("a", "b")
    }

    @Test
    fun `Int`() {
        val config = config("value" to 987654321)
        val data = IntData(987654321)
        assertThat(config.parseAs<IntData>()).isEqualTo(data)
        assertThat(data.toConfig()).isEqualTo(config)
    }

    @Test
    fun `List of Int`() {
        testValueList<IntListData>(1, 2)
    }

    @Test
    fun `Long`() {
        val config = config("value" to Long.MAX_VALUE)
        val data = LongData(Long.MAX_VALUE)
        assertThat(config.parseAs<LongData>()).isEqualTo(data)
        assertThat(data.toConfig()).isEqualTo(config)
    }

    @Test
    fun `List of Long`() {
        testValueList<LongListData>(Long.MAX_VALUE, Long.MIN_VALUE)
    }

    @Test
    fun `Double`() {
        val config = config("value" to 1.2345)
        val data = DoubleData(1.2345)
        assertThat(config.parseAs<DoubleData>()).isEqualTo(data)
        assertThat(data.toConfig()).isEqualTo(config)
    }

    @Test
    fun `List of Double`() {
        testValueList<DoubleListData>(1.2, 2.3)
    }

    @Test
    fun `Boolean true`() {
        val config = config("value" to true)
        val data = BooleanData(true)
        assertThat(config.parseAs<BooleanData>()).isEqualTo(data)
        assertThat(data.toConfig()).isEqualTo(config)
    }

    @Test
    fun `Boolean false`() {
        val config = config("value" to false)
        val data = BooleanData(false)
        assertThat(config.parseAs<BooleanData>()).isEqualTo(data)
        assertThat(data.toConfig()).isEqualTo(config)
    }

    @Test
    fun `List of Boolean`() {
        testValueList<BooleanListData>(true, false)
    }

    @Test
    fun `LocalDate`() {
        val now = LocalDate.now()
        val config = config("value" to now.toString())
        val data = LocalDateData(now)
        assertThat(config.parseAs<LocalDateData>()).isEqualTo(data)
        assertThat(data.toConfig()).isEqualTo(config)
    }

    @Test
    fun `List of LocalDate`() {
        testValueList<LocalDateListData>(LocalDate.now(), LocalDate.now().plusDays(1), valuesToString = true)
    }

    @Test
    fun `Instant`() {
        val now = Instant.now()
        val config = config("value" to now.toString())
        val data = InstantData(now)
        assertThat(config.parseAs<InstantData>()).isEqualTo(data)
        assertThat(data.toConfig()).isEqualTo(config)
    }

    @Test
    fun `List of Instant`() {
        testValueList<InstantListData>(Instant.now(), Instant.now().plusMillis(100), valuesToString = true)
    }

    @Test
    fun `HostAndPort property`() {
        val config = config("value" to "localhost:2223")
        val data = HostAndPortData(HostAndPort.fromParts("localhost", 2223))
        assertThat(config.parseAs<HostAndPortData>()).isEqualTo(data)
        assertThat(data.toConfig()).isEqualTo(config)
    }

    @Test
    fun `List of HostAndPort`() {
        testValueList<HostAndPortListData>(
                HostAndPort.fromParts("localhost", 2223),
                HostAndPort.fromParts("localhost", 2225),
                valuesToString = true)
    }

    @Test
    fun `Path`() {
        val path = Paths.get("tmp") / "test" / "file"
        val config = config("value" to path.toString())
        val data = PathData(path)
        assertThat(config.parseAs<PathData>()).isEqualTo(data)
        assertThat(data.toConfig()).isEqualTo(config)
    }

    @Test
    fun `List of Path`() {
        val path = Paths.get("tmp") / "test"
        testValueList<PathListData>(path, path / "file", valuesToString = true)
    }

    @Test
    fun `URL`() {
        val config = config("value" to "http://localhost:1234")
        val data = URLData(URL("http://localhost:1234"))
        assertThat(config.parseAs<URLData>()).isEqualTo(data)
        assertThat(data.toConfig()).isEqualTo(config)
    }

    @Test
    fun `List of URL`() {
        testValueList<URLListData>(URL("http://localhost:1234"), URL("http://localhost:1235"), valuesToString = true)
    }

    @Test
    fun `flat Properties`() {
        val config = config("value" to mapOf("key" to "value"))
        val data = PropertiesData(Properties().apply { this["key"] = "value" })
        assertThat(config.parseAs<PropertiesData>()).isEqualTo(data)
        assertThat(data.toConfig()).isEqualTo(config)
    }

    @Test
    fun `nested Properties`() {
        val config = config("value" to mapOf("first" to mapOf("second" to "value")))
        val data = PropertiesData(Properties().apply { this["first.second"] = "value" })
        assertThat(config.parseAs<PropertiesData>()).isEqualTo(data)
        assertThat(data.toConfig()).isEqualTo(config)
    }

    @Test
    fun `List of Properties`() {
        val config = config("values" to listOf(emptyMap(), mapOf("key" to "value")))
        val data = PropertiesListData(listOf(
                Properties(),
                Properties().apply { this["key"] = "value" }))
        assertThat(config.parseAs<PropertiesListData>()).isEqualTo(data)
        assertThat(data.toConfig()).isEqualTo(config)
    }

    @Test
    fun `Set`() {
        val data = StringSetData(setOf("a", "b"))
        assertThat(config("values" to listOf("a", "a", "b")).parseAs<StringSetData>()).isEqualTo(data)
        assertThat(data.toConfig()).isEqualTo(config("values" to listOf("a", "b")))
    }

    @Test
    fun `two property object`() {
        val config = config("i" to 123, "b" to true)
        val data = DualData(123, true)
        assertThat(config.parseAs<DualData>()).isEqualTo(data)
        assertThat(data.toConfig()).isEqualTo(config)
    }

    @Test
    fun `object graph`() {
        val config = config(
                "first" to mapOf(
                        "value" to "nested"))
        val data = NestedData(StringData("nested"))
        assertThat(config.parseAs<NestedData>()).isEqualTo(data)
        assertThat(data.toConfig()).isEqualTo(config)
    }

    @Test
    fun `List of objects`() {
        val config = config(
                "list" to listOf(
                        mapOf("value" to "1"),
                        mapOf("value" to "2")))
        val data = DataListData(listOf(StringData("1"), StringData("2")))
        assertThat(config.parseAs<DataListData>()).isEqualTo(data)
        assertThat(data.toConfig()).isEqualTo(config)
    }

    @Test
    fun `default value property`() {
        assertThat(config("a" to 3).parseAs<DefaultData>()).isEqualTo(DefaultData(3, 2))
        assertThat(config("a" to 3, "defaultOfTwo" to 3).parseAs<DefaultData>()).isEqualTo(DefaultData(3, 3))
        assertThat(DefaultData(3).toConfig()).isEqualTo(config("a" to 3, "defaultOfTwo" to 2))
    }

    @Test
    fun `nullable property`() {
        assertThat(empty().parseAs<NullableData>()).isEqualTo(NullableData(null))
        assertThat(config("nullable" to null).parseAs<NullableData>()).isEqualTo(NullableData(null))
        assertThat(config("nullable" to "not null").parseAs<NullableData>()).isEqualTo(NullableData("not null"))
        assertThat(NullableData(null).toConfig()).isEqualTo(empty())
    }

    private inline fun <reified T : ListData<Any>> testValueList(value1: Any, value2: Any, valuesToString: Boolean = false) {
        val values = listOf(value1, value2)
        val configValues = if (valuesToString) values.map(Any::toString) else values
        val constructor = T::class.primaryConstructor!!
        for (n in 0..2) {
            val config = config("values" to configValues.take(n))
            val data = constructor.call(values.take(n))
            assertThat(config.parseAs<T>()).isEqualTo(data)
            assertThat(data.toConfig()).isEqualTo(config)
        }
    }

    private fun config(vararg values: Pair<String, *>): Config {
        val config = ConfigValueFactory.fromMap(mapOf(*values))
        println(config.render(defaults().setOriginComments(false)))
        return config.toConfig()
    }

    private interface ListData<out T> {
        @Suppress("unused")
        val values: List<T>
    }

    data class StringData(val value: String)
    data class StringListData(override val values: List<String>) : ListData<String>
    data class StringSetData(val values: Set<String>)
    data class IntData(val value: Int)
    data class IntListData(override val values: List<Int>) : ListData<Int>
    data class LongData(val value: Long)
    data class LongListData(override val values: List<Long>) : ListData<Long>
    data class DoubleData(val value: Double)
    data class DoubleListData(override val values: List<Double>) : ListData<Double>
    data class BooleanData(val value: Boolean)
    data class BooleanListData(override val values: List<Boolean>) : ListData<Boolean>
    data class LocalDateData(val value: LocalDate)
    data class LocalDateListData(override val values: List<LocalDate>) : ListData<LocalDate>
    data class InstantData(val value: Instant)
    data class InstantListData(override val values: List<Instant>) : ListData<Instant>
    data class HostAndPortData(val value: HostAndPort)
    data class HostAndPortListData(override val values: List<HostAndPort>) : ListData<HostAndPort>
    data class PathData(val value: Path)
    data class PathListData(override val values: List<Path>) : ListData<Path>
    data class URLData(val value: URL)
    data class URLListData(override val values: List<URL>) : ListData<URL>
    data class PropertiesData(val value: Properties)
    data class PropertiesListData(override val values: List<Properties>) : ListData<Properties>
    data class DualData(val i: Int, val b: Boolean)
    data class NestedData(val first: StringData)
    data class DataListData(val list: List<StringData>)
    data class DefaultData(val a: Int, val defaultOfTwo: Int = 2)
    data class NullableData(val nullable: String?)
}