package net.corda.node.services.config

import com.google.common.net.HostAndPort
import com.typesafe.config.Config
import net.corda.core.div
import net.corda.core.node.services.ServiceInfo
import net.corda.node.internal.NetworkMapInfo
import net.corda.node.internal.Node
import net.corda.node.serialization.NodeClock
import net.corda.node.services.User
import net.corda.node.services.network.NetworkMapService
import net.corda.node.utilities.TestClock
import java.net.URL
import java.nio.file.Path
import java.util.*

interface SSLConfiguration {
    val keyStorePassword: String
    val trustStorePassword: String
    val certificatesDirectory: Path
    val keyStoreFile: Path get() = certificatesDirectory / "sslkeystore.jks"
    val trustStoreFile: Path get() = certificatesDirectory / "truststore.jks"
}

interface NodeConfiguration : SSLConfiguration {
    val baseDirectory: Path
    override val certificatesDirectory: Path get() = baseDirectory / "certificates"
    val myLegalName: String
    val networkMapService: NetworkMapInfo?
    val nearestCity: String
    val emailAddress: String
    val exportJMXto: String
    val dataSourceProperties: Properties
    val rpcUsers: List<User>
    val devMode: Boolean
    val certificateSigningService: URL
}

/**
 * [baseDirectory] is not retrieved from the config file but rather from a command line argument.
 */
class FullNodeConfiguration(override val baseDirectory: Path, val config: Config) : NodeConfiguration {
    override val myLegalName: String by config
    override val nearestCity: String by config
    override val emailAddress: String by config
    override val exportJMXto: String get() = "http"
    override val keyStorePassword: String by config
    override val trustStorePassword: String by config
    override val dataSourceProperties: Properties by config
    override val devMode: Boolean by config.orElse { false }
    override val certificateSigningService: URL by config
    override val networkMapService: NetworkMapInfo? by config.orElse { null }
    override val rpcUsers: List<User> by config.orElse { emptyList<User>() }
    val useHTTPS: Boolean by config
    val artemisAddress: HostAndPort by config
    val webAddress: HostAndPort by config
    // TODO This field is slightly redundant as artemisAddress is sufficient to hold the address of the node's MQ broker.
    // Instead this should be a Boolean indicating whether that broker is an internal one started by the node or an external one
    val messagingServerAddress: HostAndPort? by config.orElse { null }
    // TODO Make this Set<ServiceInfo>
    val extraAdvertisedServiceIds: List<String> by config
    val useTestClock: Boolean by config.orElse { false }
    val notaryNodeAddress: HostAndPort? by config.orElse { null }
    val notaryClusterAddresses: List<HostAndPort> by config.orElse { emptyList<HostAndPort>() }
    init {
        // TODO Move this to ArtemisMessagingServer
        rpcUsers.forEach {
            require(it.username.matches("\\w+".toRegex())) { "Username ${it.username} contains invalid characters" }
        }
    }

    fun createNode(): Node {
        // This is a sanity feature do not remove.
        require(!useTestClock || devMode) { "Cannot use test clock outside of dev mode" }

        val advertisedServices = extraAdvertisedServiceIds
                .filter(String::isNotBlank)
                .map { ServiceInfo.parse(it) }
                .toMutableSet()
        if (networkMapService == null) advertisedServices.add(ServiceInfo(NetworkMapService.type))

        return Node(this, advertisedServices, if (useTestClock) TestClock() else NodeClock())
    }
}
