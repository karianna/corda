package net.corda.node.services.statemachine

import net.corda.core.crypto.Party
import net.corda.core.flows.FlowException
import net.corda.core.serialization.CordaSerializable
import net.corda.core.utilities.UntrustworthyData

interface SessionMessage

@CordaSerializable
data class SessionInit(val initiatorSessionId: Long, val flowName: String, val firstPayload: Any?) : SessionMessage

interface ExistingSessionMessage : SessionMessage {
    val recipientSessionId: Long
}

@CordaSerializable
data class SessionData(override val recipientSessionId: Long, val payload: Any) : ExistingSessionMessage {
    override fun toString(): String = "${javaClass.simpleName}(recipientSessionId=$recipientSessionId, payload=$payload)"
}

interface SessionInitResponse : ExistingSessionMessage {
    val initiatorSessionId: Long
    override val recipientSessionId: Long get() = initiatorSessionId
}

@CordaSerializable
data class SessionConfirm(override val initiatorSessionId: Long, val initiatedSessionId: Long) : SessionInitResponse

@CordaSerializable
data class SessionReject(override val initiatorSessionId: Long, val errorMessage: String) : SessionInitResponse

interface SessionEnd : ExistingSessionMessage
@CordaSerializable
data class NormalSessionEnd(override val recipientSessionId: Long) : SessionEnd

@CordaSerializable
data class ErrorSessionEnd(override val recipientSessionId: Long, val errorResponse: FlowException?) : SessionEnd

@CordaSerializable
data class ReceivedSessionMessage<out M : ExistingSessionMessage>(val sender: Party, val message: M)

fun <T> ReceivedSessionMessage<SessionData>.checkPayloadIs(type: Class<T>): UntrustworthyData<T> {
    if (type.isInstance(message.payload)) {
        return UntrustworthyData(type.cast(message.payload))
    } else {
        throw FlowSessionException("We were expecting a ${type.name} from $sender but we instead got a " +
                "${message.payload.javaClass.name} (${message.payload})")
    }
}

@CordaSerializable
class FlowSessionException(message: String) : RuntimeException(message)
