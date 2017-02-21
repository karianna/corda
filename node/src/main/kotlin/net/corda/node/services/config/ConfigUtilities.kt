// TODO: Remove when configureTestSSL() is moved.
@file:JvmName("ConfigUtilities")

package net.corda.node.services.config

import com.google.common.net.HostAndPort
import com.typesafe.config.*
import net.corda.core.copyTo
import net.corda.core.createDirectories
import net.corda.core.crypto.X509Utilities
import net.corda.core.div
import net.corda.core.exists
import net.corda.core.utilities.loggerFor
import java.lang.reflect.ParameterizedType
import java.lang.reflect.Type
import java.lang.reflect.WildcardType
import java.net.URL
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.time.Instant
import java.time.LocalDate
import java.time.temporal.Temporal
import java.util.*
import kotlin.reflect.KProperty
import kotlin.reflect.jvm.javaType
import kotlin.reflect.primaryConstructor

object ConfigHelper {
    private val log = loggerFor<ConfigHelper>()

    fun loadConfig(baseDirectory: Path,
                   configFile: Path = baseDirectory / "node.conf",
                   allowMissingConfig: Boolean = false,
                   configOverrides: Map<String, Any?> = emptyMap()): Config {
        val parseOptions = ConfigParseOptions.defaults()
        val defaultConfig = ConfigFactory.parseResources("reference.conf", parseOptions.setAllowMissing(false))
        val appConfig = ConfigFactory.parseFile(configFile.toFile(), parseOptions.setAllowMissing(allowMissingConfig))
        val overrideConfig = ConfigFactory.parseMap(configOverrides + mapOf(
                // Add substitution values here
                "basedir" to baseDirectory.toString())
        )
        val finalConfig = overrideConfig
                .withFallback(appConfig)
                .withFallback(defaultConfig)
                .resolve()
        log.info("Config:\n${finalConfig.root().render(ConfigRenderOptions.defaults())}")
        return finalConfig
    }
}

operator fun <T> Config.getValue(receiver: Any, metadata: KProperty<*>): T {
    return getValueInternal(metadata.name, metadata.returnType.javaType)
}

@Suppress("UNCHECKED_CAST")
private fun <T> Config.getValueInternal(path: String, type: Type): T {
    return when (type) {
        String::class.java -> getString(path)
        Int::class.java -> getInt(path)
        Long::class.java -> getLong(path)
        Double::class.java -> getDouble(path)
        Boolean::class.java -> getBoolean(path)
        LocalDate::class.java -> LocalDate.parse(getString(path))
        Instant::class.java -> Instant.parse(getString(path))
        HostAndPort::class.java -> HostAndPort.fromString(getString(path))
        Path::class.java -> Paths.get(getString(path))
        URL::class.java -> URL(getString(path))
        Properties::class.java -> getConfig(path).toProperties()
        is ParameterizedType -> getParameterisedValue<T>(path, type)
        else -> getConfig(path).parseAs(type as Class<*>)
    } as T
}

@Suppress("UNCHECKED_CAST", "PLATFORM_CLASS_MAPPED_TO_KOTLIN")
private fun <T> Config.getParameterisedValue(path: String, type: ParameterizedType): T {
    val rawType = type.rawType as Class<*>
    require(rawType == List::class.java || rawType == Set::class.java) { "$rawType is not supported" }
    val elementType = type.actualTypeArguments[0].run {
        when (this) {
            is Class<*> -> this
            // Oddly this is needed for two of the tests to pass even though they're List<Path> and List<Properties>.
            // Perhaps this is a bug with the Kotlin compiler.
            is WildcardType -> upperBounds[0] as Class<*>
            else -> throw IllegalArgumentException("$this is not supported")
        }
    }
    val values: List<Any> = when (elementType) {
        String::class.java -> getStringList(path)
        java.lang.Integer::class.java -> getIntList(path)
        java.lang.Long::class.java -> getLongList(path)
        java.lang.Double::class.java -> getDoubleList(path)
        java.lang.Boolean::class.java -> getBooleanList(path)
        LocalDate::class.java -> getStringList(path).map(LocalDate::parse)
        Instant::class.java -> getStringList(path).map(Instant::parse)
        HostAndPort::class.java -> getStringList(path).map(HostAndPort::fromString)
        Path::class.java -> getStringList(path).map { Paths.get(it) }
        URL::class.java -> getStringList(path).map(::URL)
        Properties::class.java -> getConfigList(path).map(Config::toProperties)
        else -> getConfigList(path).map { it.parseAs(elementType) }
    }
    return (if (rawType == Set::class.java) values.toSet() else values) as T
}

fun Config.toProperties(): Properties = entrySet().associateByTo(Properties(), { it.key }, { it.value.unwrapped().toString() })

fun <T : Any> Config.parseAs(type: Class<T>): T {
    val constructor = type.kotlin.primaryConstructor ?: throw IllegalArgumentException("${type.name} has no constructors")
    val args = constructor.parameters
            .filterNot { it.isOptional && !hasPath(it.name!!) }
            .associateBy({ it }) {
                if (it.type.isMarkedNullable && !hasPath(it.name!!)) {
                    null
                } else {
                    getValueInternal<Any>(it.name!!, it.type.javaType)
                }
            }
    return constructor.callBy(args)
}

/**
 *
 */
inline fun <reified T : Any> Config.parseAs(): T = parseAs(T::class.java)

/**
 *
 */
fun Any.toConfig(): Config = ConfigValueFactory.fromMap(toValueMap()).toConfig()

@Suppress("UNCHECKED_CAST", "PLATFORM_CLASS_MAPPED_TO_KOTLIN")
private fun Any.toValueMap(): Map<String, Any> {
    val values = HashMap<String, Any>()
    for (field in javaClass.declaredFields) {
        if (field.isSynthetic) continue
        field.isAccessible = true
        val value = field.get(this) ?: continue
        val configValue = if (value is String || value is Boolean || value is Number) {
            value
        } else if (value is Temporal || value is HostAndPort || value is Path || value is URL) {
            value.toString()
        } else if (value is Properties) {
            ConfigFactory.parseMap(value as Map<String, Any>).root()
        } else if (value is Iterable<*>) {
            val elementType = (field.genericType as ParameterizedType).actualTypeArguments[0] as Class<*>
            val iterable = when (elementType) {
                String::class.java -> value
                java.lang.Integer::class.java -> value
                java.lang.Long::class.java -> value
                java.lang.Double::class.java -> value
                java.lang.Boolean::class.java -> value
                LocalDate::class.java -> value.map(Any?::toString)
                Instant::class.java -> value.map(Any?::toString)
                HostAndPort::class.java -> value.map(Any?::toString)
                Path::class.java -> value.map(Any?::toString)
                URL::class.java -> value.map(Any?::toString)
                Properties::class.java -> value.map { ConfigFactory.parseMap(it as Map<String, Any>).root() }
                else -> value.map { it?.toValueMap() }
            }
            ConfigValueFactory.fromIterable(iterable)
        } else {
            value.toValueMap()
        }
        values[field.name] = configValue
    }
    return values
}

/**
 * Helper class for optional configurations
 */
class OptionalConfig<out T>(val config: Config, val default: () -> T) {
    operator fun getValue(receiver: Any, metadata: KProperty<*>): T {
        return if (config.hasPath(metadata.name)) config.getValue(receiver, metadata) else default()
    }
}

fun <T> Config.orElse(default: () -> T): OptionalConfig<T> = OptionalConfig(this, default)

/**
 * Strictly for dev only automatically construct a server certificate/private key signed from
 * the CA certs in Node resources. Then provision KeyStores into certificates folder under node path.
 */
fun NodeConfiguration.configureWithDevSSLCertificate() = configureDevKeyAndTrustStores(myLegalName)

private fun SSLConfiguration.configureDevKeyAndTrustStores(myLegalName: String) {
    certificatesDirectory.createDirectories()
    if (!trustStoreFile.exists()) {
        javaClass.classLoader.getResourceAsStream("net/corda/node/internal/certificates/cordatruststore.jks").copyTo(trustStoreFile)
    }
    if (!keyStoreFile.exists()) {
        val caKeyStore = X509Utilities.loadKeyStore(
                javaClass.classLoader.getResourceAsStream("net/corda/node/internal/certificates/cordadevcakeys.jks"),
                "cordacadevpass")
        X509Utilities.createKeystoreForSSL(keyStoreFile, keyStorePassword, keyStorePassword, caKeyStore, "cordacadevkeypass", myLegalName)
    }
}

// TODO Move this to CoreTestUtils.kt once we can pry this from the explorer
@JvmOverloads
fun configureTestSSL(legalName: String = "Mega Corp."): SSLConfiguration = object : SSLConfiguration {
    override val certificatesDirectory = Files.createTempDirectory("certs")
    override val keyStorePassword: String get() = "cordacadevpass"
    override val trustStorePassword: String get() = "trustpass"

    init {
        configureDevKeyAndTrustStores(legalName)
    }
}
