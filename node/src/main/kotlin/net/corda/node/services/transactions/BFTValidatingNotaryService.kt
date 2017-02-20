package net.corda.node.services.transactions

import bftsmart.tom.MessageContext
import bftsmart.tom.ServiceProxy
import bftsmart.tom.ServiceReplica
import bftsmart.tom.core.messages.TOMMessage
import bftsmart.tom.server.defaultservices.DefaultRecoverable
import bftsmart.tom.server.defaultservices.DefaultReplier
import bftsmart.tom.util.Extractor
import co.paralleluniverse.fibers.Suspendable
import com.google.common.net.HostAndPort
import net.corda.core.contracts.StateRef
import net.corda.core.contracts.Timestamp
import net.corda.core.contracts.TransactionVerificationException
import net.corda.core.crypto.*
import net.corda.core.flows.FlowLogic
import net.corda.core.node.services.TimestampChecker
import net.corda.core.node.services.UniquenessProvider
import net.corda.core.serialization.SingletonSerializeAsToken
import net.corda.core.serialization.deserialize
import net.corda.core.serialization.serialize
import net.corda.core.transactions.SignedTransaction
import net.corda.core.transactions.WireTransaction
import net.corda.core.utilities.loggerFor
import net.corda.core.utilities.unwrap
import net.corda.flows.NotaryError
import net.corda.flows.NotaryException
import net.corda.flows.NotaryFlow
import net.corda.flows.ResolveTransactionsFlow
import net.corda.node.services.api.ServiceHubInternal
import net.corda.node.utilities.JDBCHashMap
import net.corda.node.utilities.databaseTransaction
import org.jetbrains.exposed.sql.Database
import java.security.SignatureException
import java.util.*
import kotlin.concurrent.thread

/**
 * A validating notary service operated by a group of parties that don't necessarily trust each other.
 *
 * To validate a transaction, this service collects proofs that the transaction has been validated and committed by a
 * specified number of notary nodes.
 *
 * Based on the [bft-smart library](https://github.com/bft-smart/library).
 */

class BFTValidatingNotaryService(val services: ServiceHubInternal,
                                 val timestampChecker: TimestampChecker,
                                 val myAddress: HostAndPort,
                                 val clusterAddresses: List<HostAndPort>,
                                 val db: Database,
                                 val serviceProxy: ServiceProxyWrapper) : SingletonSerializeAsToken() {

    init {
        services.registerFlowInitiator(NotaryFlow.Client::class, {
            Service(it, serviceProxy)
        })

        require(myAddress in clusterAddresses) {
            "expected myAddress '$myAddress' to be listed in clusterAddresses '$clusterAddresses'"
        }
        startServerThread()
    }

    companion object {
        val type = ValidatingNotaryService.type.getSubType("bft")
        private val log = loggerFor<BFTValidatingNotaryService>()
    }

    class ServiceProxyWrapper(myAddress: HostAndPort,
                              clusterAddresses: List<HostAndPort>) : SingletonSerializeAsToken(), UniquenessProvider {

        val clientId = 10000 + clusterAddresses.indexOf(myAddress)
        val proxy: ServiceProxy by lazy { buildProxy() }

        fun buildProxy(): ServiceProxy {
            val comparator = Comparator<ByteArray> { o1, o2 ->
                val reply1 = o1.deserialize<ReplicaResponse>()
                val reply2 = o2.deserialize<ReplicaResponse>()

                // TODO: implement proper comparison
                if (reply1 is ReplicaResponse.Error && reply2 is ReplicaResponse.Error) {
                    0
//                    println("ERRORS: ${reply1.error} ${reply2.error}, is equal = " + (reply1.error == reply2.error))
//                    if (reply1.error == reply2.error) 0 else -1
                } else {
                    if (reply1 is ReplicaResponse.Signature && reply2 is ReplicaResponse.Signature) 0 else -1
                }
            }

            val extractor = Extractor { replies, sameContent, lastReceived ->
                val rep = replies.mapNotNull { it?.content?.deserialize<ReplicaResponse>() }

                val sigs = rep.filterIsInstance<ReplicaResponse.Signature>()
                val conflicts = rep.filterIsInstance<ReplicaResponse.Error>()

                println("$clientId: signature replies: ${sigs.size}, error: ${conflicts.size}")

                // TODO: if majority are signature replies, return an aggregate
                val respo = if (sigs.isNotEmpty()) {
                    ClusterResponse.Signatures(sigs.map { it.txSig })
                } else ClusterResponse.Error(conflicts.first().error)

                val content = respo.serialize().bytes
                val reply = replies[lastReceived]

                TOMMessage(reply.sender, reply.session, reply.sequence, content, reply.viewID)
            }

            return ServiceProxy(clientId, "bft-smart-config", comparator, extractor)
        }

        override fun commit(states: List<StateRef>, txId: SecureHash, callerIdentity: Party) {
            throw UnsupportedOperationException("not implemented")
        }
    }

    private val serverId: Int = clusterAddresses.indexOf(myAddress)

    private fun startServerThread() {
        thread(name = "BFTSmartServer-$serverId", isDaemon = true) {
            Server(serverId, db, "bft_smart_notary_committed_states", services, timestampChecker)
        }
    }

    data class CommitRequest<out T>(val tx: T, val callerIdentity: Party)

    sealed class ReplicaResponse {
        class Error(val error: NotaryError) : ReplicaResponse()
        class Signature(val txSig: DigitalSignature) : ReplicaResponse()
    }

    sealed class ClusterResponse {
        class Error(val error: NotaryError) : ClusterResponse()
        class Signatures(val txSigs: List<DigitalSignature>) : ClusterResponse()
    }

    class Service(val otherSide: Party, val serviceProxy: ServiceProxyWrapper) : FlowLogic<Unit>() {

        @Suspendable
        override fun call() {
            val stx = receive<SignedTransaction>(otherSide).unwrap { it }
            val sigs = commit(stx)
            send(otherSide, sigs)
        }

        fun commit(stx: SignedTransaction): List<DigitalSignature> {
            val request = CommitRequest(stx, otherSide)
            val responseBytes = serviceProxy.proxy.invokeOrdered(request.serialize().bytes)
            val response = responseBytes.deserialize<ClusterResponse>()

            if (response is ClusterResponse.Error) {
                throw NotaryException(response.error)
            }

            val sigs = (response as ClusterResponse.Signatures).txSigs

            log.debug("All input states of transaction ${stx.id} have been committed")
            return sigs
        }
    }

    class Server(val id: Int,
                 val db: Database,
                 tableName: String,
                 val services: ServiceHubInternal,
                 val timestampChecker: TimestampChecker) : DefaultRecoverable() {
        // TODO: Exception handling when processing client input.

        val commitLog = databaseTransaction(db) { JDBCHashMap<StateRef, UniquenessProvider.ConsumingTx>(tableName) }
        val replica: ServiceReplica = ServiceReplica(id, "bft-smart-config", this, this, null, DefaultReplier())

        init {
            println(id)
        }

        override fun appExecuteUnordered(command: ByteArray, msgCtx: MessageContext): ByteArray? {
            throw NotImplementedError()
        }

        override fun appExecuteBatch(command: Array<ByteArray>, mcs: Array<MessageContext>): Array<ByteArray?> {
            val replies = command.zip(mcs) { c, m ->
                executeSingle(c)
            }
            return replies.toTypedArray()
        }

        private fun executeSingle(command: ByteArray): ByteArray? {
            val request = command.deserialize<CommitRequest<SignedTransaction>>()
            val stx = request.tx
            val response = processTx(stx, request.callerIdentity)

            return response.serialize().bytes
        }

        fun processTx(stx: SignedTransaction, callerIdentity: Party): ReplicaResponse {
            val response = try {
                checkSignatures(stx)

                val wtx = stx.tx
                validateTimestamp(wtx.timestamp)

                validateTransaction(wtx, callerIdentity)

                val states = wtx.inputs

                commit(states, wtx.id, callerIdentity)

                val sig = sign(wtx.id.bytes)
                ReplicaResponse.Signature(sig)

            } catch (e: NotaryException) {
                ReplicaResponse.Error(e.error)
            }
            return response
        }

        fun commit(states: List<StateRef>, txId: SecureHash, callerIdentity: Party) {
            val conflicts = mutableMapOf<StateRef, UniquenessProvider.ConsumingTx>()
            databaseTransaction(db) {
                states.forEach { state ->
                    commitLog[state]?.let { conflicts[state] = it }
                }
                if (conflicts.isEmpty()) {
                    states.forEachIndexed { i, stateRef ->
                        val txInfo = UniquenessProvider.ConsumingTx(txId, i, callerIdentity)
                        commitLog.put(stateRef, txInfo)
                    }
                } else {
                    val conflict = UniquenessProvider.Conflict(conflicts)
                    val conflictData = conflict.serialize()
                    val signedConflict = SignedData(conflictData, sign(conflictData.bytes))
                    throw NotaryException(NotaryError.Conflict(txId, signedConflict))
                }
            }
        }

        private fun validateTimestamp(t: Timestamp?) {
            if (t != null && !timestampChecker.isValid(t))
                throw NotaryException(NotaryError.TimestampInvalid())
        }

        private fun checkSignatures(stx: SignedTransaction) {
            try {
                stx.verifySignatures(services.myInfo.notaryIdentity.owningKey)
            } catch(e: SignedTransaction.SignaturesMissingException) {
                throw NotaryException(NotaryError.SignaturesMissing(e))
            }
        }

        fun validateTransaction(wtx: WireTransaction, party: Party) {
            try {
                resolveTransaction(wtx, party)
                wtx.toLedgerTransaction(services).verify()
            } catch (e: Exception) {
                throw when (e) {
                    is TransactionVerificationException -> NotaryException(NotaryError.TransactionInvalid(e.toString()))
                    is SignatureException -> NotaryException(NotaryError.SignaturesInvalid(e.toString()))
                    else -> e
                }
            }
        }

        private fun resolveTransaction(wtx: WireTransaction, party: Party) {
            services.startFlow(ResolveTransactionsFlow(wtx, party)).resultFuture.get()
        }


        private fun sign(bytes: ByteArray): DigitalSignature.WithKey {
            val mySigningKey = databaseTransaction(db) { services.notaryIdentityKey }
            return mySigningKey.signWithECDSA(bytes)
        }


        // TODO:
        // - Test snapshot functionality with different bft-smart cluster configurations.
        // - Add streaming to support large data sets.
        override fun getSnapshot(): ByteArray {
            // LinkedHashMap for deterministic serialisation
            val m = LinkedHashMap<StateRef, UniquenessProvider.ConsumingTx>()
            databaseTransaction(db) {
                commitLog.forEach { m[it.key] = it.value }
            }
            return m.serialize().bytes
        }

        override fun installSnapshot(bytes: ByteArray) {
            val m = bytes.deserialize<LinkedHashMap<StateRef, UniquenessProvider.ConsumingTx>>()
            databaseTransaction(db) {
                commitLog.clear()
                commitLog.putAll(m)
            }
        }
    }
}
