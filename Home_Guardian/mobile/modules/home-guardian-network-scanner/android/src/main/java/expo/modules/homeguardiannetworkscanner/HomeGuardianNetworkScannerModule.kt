package expo.modules.homeguardiannetworkscanner

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.util.Log
import androidx.annotation.RequiresApi
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import java.io.File
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.MulticastSocket
import java.net.NetworkInterface
import java.net.Socket
import java.nio.charset.Charset
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.UUID
import java.util.concurrent.Callable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.math.min

internal const val NATIVE_SCAN_HOST_HARD_CAP = 512
private const val MAX_FINGERPRINTS_PER_DEVICE = 128
private const val MAX_NSD_COLLECTED_SERVICES = 512

class HomeGuardianNetworkScannerModule : Module() {
  override fun definition() = ModuleDefinition {
    Name("HomeGuardianNetworkScanner")

    AsyncFunction("scanNetworkAsync") { options: Map<String, Any?> ->
      val context = appContext.reactContext
        ?: throw IllegalStateException("React context is not available.")

      AndroidLanScanner(context).scan(options)
    }
  }
}

private data class NetworkSnapshot(
  val context: Map<String, Any?>,
  val wifiNetwork: Network?,
  val wifiInterfaceName: String?,
)

internal enum class ObservationPriority(val rank: Int) {
  TCP_ONLY(0),
  STRUCTURED_DISCOVERY(1),
  FRESH_NEIGHBOR(2),
  GATEWAY(3),
}

/**
 * The LAN is untrusted input. Keep the final native observation map strictly
 * bounded and let current physical/structured evidence replace TCP-only rows
 * when the bound is reached. No address or fingerprint is included in the
 * overflow counters.
 */
internal class BoundedObservationMap(
  private val gatewayIp: String?,
  requestedLimit: Int = NATIVE_SCAN_HOST_HARD_CAP,
) : LinkedHashMap<String, MutableDevice>() {
  val hardLimit: Int = requestedLimit.coerceIn(1, NATIVE_SCAN_HOST_HARD_CAP)
  var overflowEvents: Int = 0
    private set
  var droppedHosts: Int = 0
    private set
  var evictedLowerPriorityHosts: Int = 0
    private set
  var receiveBufferDrops: Int = 0
    private set

  val capacityExceeded: Boolean
    get() = overflowEvents > 0 || receiveBufferDrops > 0

  fun observe(host: String, priority: ObservationPriority): MutableDevice? {
    if (host.isBlank()) return null
    val effectivePriority = if (host == gatewayIp) ObservationPriority.GATEWAY else priority
    get(host)?.let { existing ->
      existing.promoteObservationPriority(effectivePriority)
      return existing
    }

    if (size < hardLimit) {
      return MutableDevice(host).also { device ->
        device.promoteObservationPriority(effectivePriority)
        put(host, device)
      }
    }

    overflowEvents += 1
    val victim = values
      .filter { it.observationPriority.rank < effectivePriority.rank }
      .minByOrNull { it.observationPriority.rank }
    if (victim == null) {
      droppedHosts += 1
      return null
    }

    remove(victim.ipAddress)
    evictedLowerPriorityHosts += 1
    return MutableDevice(host).also { device ->
      device.promoteObservationPriority(effectivePriority)
      put(host, device)
    }
  }

  fun recordReceiveBufferDrop() {
    receiveBufferDrops += 1
  }
}

private class BoundedLinkedHashSet<E>(private val hardLimit: Int) : AbstractMutableSet<E>() {
  private val delegate = LinkedHashSet<E>()

  override val size: Int
    get() = delegate.size

  override fun iterator(): MutableIterator<E> = delegate.iterator()

  override fun add(element: E): Boolean {
    if (delegate.contains(element)) return false
    if (delegate.size >= hardLimit) {
      val incomingPriority = fingerprintRetentionPriority(element)
      val victim = delegate.firstOrNull { existing ->
        fingerprintRetentionPriority(existing) < incomingPriority
      } ?: return false
      delegate.remove(victim)
    }
    return delegate.add(element)
  }

  private fun fingerprintRetentionPriority(value: E): Int {
    val text = value as? String ?: return 0
    return when {
      text.startsWith("ssdp-usn:", ignoreCase = true) ||
        text.startsWith("upnp-udn:", ignoreCase = true) -> 2
      text.startsWith("ssdp-location:", ignoreCase = true) ||
        text.startsWith("spotify-endpoint:", ignoreCase = true) -> 1
      else -> 0
    }
  }
}

private fun getOrCreateObservation(
  discoveries: MutableMap<String, MutableDevice>,
  host: String,
  priority: ObservationPriority,
): MutableDevice? {
  if (discoveries is BoundedObservationMap) return discoveries.observe(host, priority)
  return discoveries[host]?.also { it.promoteObservationPriority(priority) }
    ?: MutableDevice(host).also { device ->
      device.promoteObservationPriority(priority)
      discoveries[host] = device
    }
}

private fun recordReceiveBufferDrop(discoveries: MutableMap<String, MutableDevice>) {
  (discoveries as? BoundedObservationMap)?.recordReceiveBufferDrop()
}

internal data class NeighborTableSnapshot(
  val entries: Map<String, String>,
  val procSourceAvailable: Boolean,
  val ipNeighborSourceAvailable: Boolean,
  val freshStateHosts: Set<String> = emptySet(),
) {
  val anySourceAvailable: Boolean
    get() = procSourceAvailable || ipNeighborSourceAvailable
}

internal data class CapturedIpv4LinkAddress(
  val address: String,
  val prefixLength: Int,
)

internal data class AuthoritativeWifiSubnet(
  val localIp: String,
  val subnetCidr: String,
  val source: String,
  val gatewayIp: String? = null,
)

/**
 * Android's process default network may be a VPN even while a Wi-Fi interface
 * has an address in the same CIDR. Every scanner-owned socket therefore goes
 * through this adapter and is bound to the Network captured for the active
 * Wi-Fi before a local bind, connect, send, or receive can happen.
 */
internal interface AuthoritativeNetworkSocketBinding {
  fun bind(socket: DatagramSocket)
  fun bind(socket: Socket)
}

private class AndroidNetworkSocketBinding(
  private val network: Network,
) : AuthoritativeNetworkSocketBinding {
  override fun bind(socket: DatagramSocket) {
    network.bindSocket(socket)
  }

  override fun bind(socket: Socket) {
    network.bindSocket(socket)
  }
}

internal data class NetworkSocketBindingSnapshot(
  val attempts: Int,
  val failures: Int,
  val suppressedAfterFailure: Int,
  val unboundPathsSkipped: Int,
  val evidencePathFailures: Int,
) {
  val requiresPartialScan: Boolean
    get() = failures > 0 || suppressedAfterFailure > 0 || evidencePathFailures > 0
}

internal class NetworkSocketBindingDiagnostics {
  private val attempts = AtomicInteger(0)
  private val failures = AtomicInteger(0)
  private val suppressedAfterFailure = AtomicInteger(0)
  private val unboundPathsSkipped = AtomicInteger(0)
  private val evidencePathFailures = AtomicInteger(0)

  fun recordAttempt() {
    attempts.incrementAndGet()
  }

  fun recordFailure() {
    failures.incrementAndGet()
  }

  fun recordSuppressedAfterFailure() {
    suppressedAfterFailure.incrementAndGet()
  }

  fun recordUnboundPathSkipped() {
    unboundPathsSkipped.incrementAndGet()
  }

  fun recordEvidencePathFailure() {
    evidencePathFailures.incrementAndGet()
  }

  fun snapshot(): NetworkSocketBindingSnapshot = NetworkSocketBindingSnapshot(
    attempts = attempts.get(),
    failures = failures.get(),
    suppressedAfterFailure = suppressedAfterFailure.get(),
    unboundPathsSkipped = unboundPathsSkipped.get(),
    evidencePathFailures = evidencePathFailures.get(),
  )
}

/**
 * Creates only unbound Java sockets, binds them to the captured Wi-Fi Network,
 * and returns them only after that binding succeeds. A binding failure closes
 * the socket and permanently fails this factory closed for the remainder of
 * the scan; callers can never fall back to the process default/VPN route.
 */
internal class WifiBoundSocketFactory(
  private val binding: AuthoritativeNetworkSocketBinding,
  private val diagnostics: NetworkSocketBindingDiagnostics,
) {
  private val bindingUnavailable = AtomicBoolean(false)

  fun openDatagram(): DatagramSocket? {
    if (bindingUnavailable.get()) {
      diagnostics.recordSuppressedAfterFailure()
      return null
    }
    val socket = try {
      DatagramSocket(null)
    } catch (_: Exception) {
      diagnostics.recordEvidencePathFailure()
      return null
    }
    diagnostics.recordAttempt()
    return try {
      binding.bind(socket)
      socket
    } catch (_: Exception) {
      bindingUnavailable.set(true)
      diagnostics.recordFailure()
      socket.close()
      null
    }
  }

  fun openMulticast(): MulticastSocket? {
    if (bindingUnavailable.get()) {
      diagnostics.recordSuppressedAfterFailure()
      return null
    }
    val socket = try {
      MulticastSocket(null)
    } catch (_: Exception) {
      diagnostics.recordEvidencePathFailure()
      return null
    }
    diagnostics.recordAttempt()
    return try {
      binding.bind(socket)
      socket
    } catch (_: Exception) {
      bindingUnavailable.set(true)
      diagnostics.recordFailure()
      socket.close()
      null
    }
  }

  fun openStream(): Socket? {
    if (bindingUnavailable.get()) {
      diagnostics.recordSuppressedAfterFailure()
      return null
    }
    val socket = try {
      Socket()
    } catch (_: Exception) {
      diagnostics.recordEvidencePathFailure()
      return null
    }
    diagnostics.recordAttempt()
    return try {
      binding.bind(socket)
      socket
    } catch (_: Exception) {
      bindingUnavailable.set(true)
      diagnostics.recordFailure()
      socket.close()
      null
    }
  }
}

private class AndroidLanScanner(private val context: Context) {
  private val defaultPorts = listOf(
    21, 22, 23, 53, 80, 139, 443, 445, 554, 631, 1400, 1443, 1900, 3702,
    5000, 5001, 7000, 7001, 7547, 7676, 8001, 8002, 8008, 8009, 8060,
    8080, 8081, 8443, 8888, 8899, 9000, 9001,
    9100, 9761, 17654, 25565, 32400, 49152, 49153, 49154, 49155, 49156, 49157
  )
  // mDNS service types: 공유기/카메라/스마트홈/도어록/플러그/허브/AirPlay/Matter/HomeKit 포함.
  private val mdnsServiceTypes = listOf(
    "_http._tcp.",
    "_https._tcp.",
    "_rtsp._tcp.",
    "_onvif._tcp.",
    "_axis-video._tcp.",
    "_hap._tcp.",
    "_homekit._tcp.",
    "_matter._tcp.",
    "_matterc._udp.",
    "_googlecast._tcp.",
    "_airplay._tcp.",
    "_raop._tcp.",
    "_companion-link._tcp.",
    "_ipp._tcp.",
    "_ipps._tcp.",
    "_smb._tcp.",
    "_workstation._tcp.",
    "_smartthings._tcp.",
    "_smarthome._tcp.",
    "_samsungmsf._tcp.",
    "_androidtvremote2._tcp.",
    "_spotify-connect._tcp.",
    // 최신 IoT: 스마트조명/음성비서/로봇청소기/미디어/프린터 mDNS 서비스 타입 추가 발견.
    "_hue._tcp.",
    "_amzn-wplay._tcp.",
    "_sonos._tcp.",
    "_roku-rcp._tcp.",
    "_viziocast._tcp.",
    "_miio._udp.",
    "_nanoleafapi._tcp.",
    "_printer._tcp.",
    "_pdl-datastream._tcp.",
    // LG ThinQ local advertisement.  The backend requires explicit product
    // evidence before it can call the device an air conditioner.
    "_lg-smart-device._tcp."
  )

  // mDNS 동시 탐색 파라미터. 한 배치에서 동시에 띄울 서비스 타입 수(NsdManager 동시 작업 한도 고려),
  // 배치당 응답 수신 window(ms), resolve 총량 상한(resolve 는 동시 한도가 엄격해 순차 처리하므로 시간 가드).
  private val MDNS_DISCOVERY_BATCH = 6
  private val MDNS_LISTEN_WINDOW_MS = 1_300L
  // A busy home network can advertise dozens of services.  The old 15-second
  // budget stopped after only a handful of 900 ms NSD resolves, which made
  // mDNS-visible devices disappear from the collected set.  Keep the cap
  // bounded, but give the resolver enough time to finish a representative
  // service set; raw mDNS discovery still records every host it can observe.
  private val MDNS_MAX_RESOLVES = 256
  private val MDNS_RESOLVE_BUDGET_MS = 30_000L
  // The DNS-SD meta-query can reveal vendor service types that are not in the
  // seed list. Follow only syntactically valid local service types, once, with
  // a strict count and wall-clock cap so an untrusted LAN cannot make scanning
  // unbounded. These queries collect advertised PTR/SRV/TXT evidence only;
  // they never map a service type to a product name or model.
  private val MDNS_MAX_DYNAMIC_SERVICE_TYPES = 24
  private val MDNS_DYNAMIC_QUERY_BUDGET_MS = 2_000L
  // A port probe is deliberately broad, but it must never hold the app in
  // "물건 확인" forever when a router drops SYN packets instead of replying.
  // A timed-out phase still returns every observation collected so far and
  // marks the result as incomplete; it never invents or hides a device.
  private val TCP_SCAN_BUDGET_MS = 45_000L

  fun scan(options: Map<String, Any?>): Map<String, Any?> {
    val started = System.currentTimeMillis()
    val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
    val networkSnapshot = buildNetworkSnapshot(wifiManager)
    val contextMap = networkSnapshot.context

    if (contextMap["is_emulator"] == true || contextMap["is_virtual_network"] == true) {
      return failedScan(
        started,
        contextMap,
        "SCAN_ACTUAL_DEVICE_REQUIRED",
      )
    }

    if (contextMap["interface_type"] != "wifi" || contextMap["is_private_network"] != true) {
      return failedScan(
        started,
        contextMap,
        "NETWORK_NOT_SCANNABLE",
      )
    }

    val wifiNetwork = networkSnapshot.wifiNetwork ?: return failedScan(
      started,
      contextMap,
      "ACTIVE_WIFI_NETWORK_MISSING",
    )
    val bindingDiagnostics = NetworkSocketBindingDiagnostics()
    val socketFactory = WifiBoundSocketFactory(
      binding = AndroidNetworkSocketBinding(wifiNetwork),
      diagnostics = bindingDiagnostics,
    )

    val localIp = contextMap["local_ip"] as? String ?: return failedScan(
      started,
      contextMap,
      "LOCAL_IP_MISSING",
    )

    val requestedMaxHosts = numberOption(options["maxHosts"], NATIVE_SCAN_HOST_HARD_CAP)
    val maxHosts = requestedMaxHosts.coerceIn(1, NATIVE_SCAN_HOST_HARD_CAP)
    val timeoutMillis = numberOption(options["timeoutMillis"], 350).coerceIn(80, 1_500)
    val ports = portsOption(options["ports"]).ifEmpty { defaultPorts }
    // The Android DHCP netmask has historically been exposed with different
    // byte orders on different vendor builds.  The human-readable CIDR from
    // LinkProperties is the authoritative local range, so use it to cap the
    // probe before any TCP socket is opened.  Without this guard a /24 phone
    // can accidentally sample 4,096 addresses and turn Internet-facing
    // banners/RTSP ports into dozens of fake household devices.
    val declaredSubnet = contextMap["subnet_cidr"] as? String ?: return failedScan(
      started,
      contextMap,
      "LOCAL_SUBNET_MISSING",
    )
    val subnetAllowlist = ActiveSubnetAllowlist.from(
      subnetCidr = declaredSubnet,
      hostResolver = { host -> wifiNetwork.getAllByName(host).toList() },
    ) ?: return failedScan(
      started,
      contextMap,
      "LOCAL_SUBNET_MISSING",
    )
    // /proc/net/arp can retain neighbours from an earlier Wi-Fi connection.
    // Filter it through the same active-subnet gate used by every multicast
    // discovery path before it can influence candidates or diagnostics.
    val neighborBeforeProbe = readNeighborTable(networkSnapshot.wifiInterfaceName)
    val arpBeforeProbe = neighborBeforeProbe.entries
      .filterKeys { subnetAllowlist.acceptObservation(it) }
    val declaredHostCount = hostCountFromCidr(declaredSubnet)
    val safeHostLimit = min(
      maxHosts.toLong(),
      (declaredHostCount ?: 254L).coerceAtMost(NATIVE_SCAN_HOST_HARD_CAP.toLong()),
    ).toInt().coerceAtLeast(1)
    val candidateHosts = buildCandidateHosts(
      localIp = localIp,
      subnetCidr = declaredSubnet,
      arpIps = arpBeforeProbe.keys,
      maxHosts = safeHostLimit,
      gatewayIp = contextMap["gateway_ip"] as? String,
    )
    val subnetHostCount = declaredHostCount
    // The local handset is intentionally excluded from probing.  Compare
    // against the number of *remote* hosts so a complete /24 is not reported
    // as incomplete merely because its own address is absent from the list.
    val expectedRemoteHostCount = subnetHostCount?.coerceAtLeast(1L)?.minus(1L) ?: 0L
    val candidateCoverageComplete =
      subnetHostCount != null &&
        expectedRemoteHostCount <= safeHostLimit.toLong() &&
        candidateHosts.size.toLong() >= expectedRemoteHostCount
    val candidateHostsTruncated =
      (expectedRemoteHostCount - candidateHosts.size.toLong()).coerceAtLeast(0L)
    val diagnostics = linkedMapOf<String, Any?>(
      "subnet_cidr" to contextMap["subnet_cidr"],
      "subnet_source" to contextMap["subnet_source"],
      "subnet_host_count" to subnetHostCount,
      "candidate_host_count" to candidateHosts.size,
      "candidate_coverage_complete" to candidateCoverageComplete,
      "candidate_hosts_truncated" to candidateHostsTruncated,
      "native_host_hard_cap" to NATIVE_SCAN_HOST_HARD_CAP,
      "requested_host_limit_raw" to requestedMaxHosts,
      "requested_host_limit" to safeHostLimit,
      "requested_port_count" to ports.size,
      "wifi_interface_name" to networkSnapshot.wifiInterfaceName,
      "arp_entries_before_probe" to arpBeforeProbe.size,
      "neighbor_proc_source_available_before" to neighborBeforeProbe.procSourceAvailable,
      "neighbor_ip_source_available_before" to neighborBeforeProbe.ipNeighborSourceAvailable,
      "neighbor_source_available_before" to neighborBeforeProbe.anySourceAvailable,
      "neighbor_proc_source_available_after" to false,
      "neighbor_ip_source_available_after" to false,
      "neighbor_source_available_after" to false,
      "neighbor_probe_complete" to false,
      "neighbor_presence_confirmed" to false,
      "neighbor_coverage_complete" to false,
      "neighbor_fresh_state_hosts" to 0,
      "neighbor_unverified_hosts" to 0,
      "arp_interface_filter_enabled" to (networkSnapshot.wifiInterfaceName != null),
      "active_subnet_filter_enabled" to true,
      "out_of_subnet_observations_dropped" to subnetAllowlist.rejectedObservationCount(),
      "wifi_network_socket_binding_required" to true,
      "wifi_network_socket_bind_attempts" to 0,
      "wifi_network_socket_bind_failures" to 0,
      "wifi_network_socket_bind_suppressed" to 0,
      "wifi_network_unbound_paths_skipped" to 0,
      "wifi_network_evidence_path_failures" to 0,
      "wifi_network_socket_binding_complete" to true,
      // Initialize the partial flags before discovery. If a later phase throws,
      // failedScan still carries the last truthful coverage state to the bridge.
      "tcp_scan_timed_out" to false,
      "tcp_transport_complete" to false,
      "tcp_probe_completed_hosts" to 0,
      "candidate_stimulation_complete" to false,
      "observation_host_limit" to NATIVE_SCAN_HOST_HARD_CAP,
      "observation_limit_reached" to false,
      "observation_overflow_events" to 0,
      "observation_hosts_dropped" to 0,
      "observation_hosts_evicted" to 0,
      "observation_receive_buffer_dropped" to 0,
      "coverage_complete" to false,
      "scan_partial" to !candidateCoverageComplete,
    )

    val multicastLock = wifiManager.createMulticastLock("HomeGuardianNetworkScan")
    multicastLock.setReferenceCounted(false)

    return try {
      multicastLock.acquire()
      val discoveries = BoundedObservationMap(
        gatewayIp = contextMap["gateway_ip"] as? String,
        requestedLimit = NATIVE_SCAN_HOST_HARD_CAP,
      )

      val beforeMdns = discoveries.size
      discoverMdns(
        discoveries,
        subnetAllowlist,
        wifiNetwork,
        socketFactory,
        bindingDiagnostics,
      )
      diagnostics["mdns_hosts"] = discoveries.size - beforeMdns
      val beforeRawMdns = discoveries.size
      discoverMdnsRaw(
        discoveries,
        subnetAllowlist,
        socketFactory,
        networkSnapshot.wifiInterfaceName,
        bindingDiagnostics,
      )
      diagnostics["mdns_raw_hosts"] = discoveries.size - beforeRawMdns
      val beforeSsdp = discoveries.size
      discoverSsdp(discoveries, subnetAllowlist, socketFactory)
      diagnostics["ssdp_hosts"] = discoveries.size - beforeSsdp
      enrichUpnpDescriptions(discoveries, subnetAllowlist, socketFactory)
      enrichSpotifyConnect(discoveries, socketFactory)
      val beforeOnvif = discoveries.size
      discoverOnvif(discoveries, subnetAllowlist, socketFactory)
      diagnostics["onvif_hosts"] = discoveries.size - beforeOnvif
      val beforeTcp = discoveries.size
      val tcpScanOutcome = scanTcpPorts(candidateHosts, ports, timeoutMillis, discoveries, socketFactory)
      diagnostics["tcp_scan_timed_out"] = tcpScanOutcome.timedOut
      diagnostics["tcp_transport_complete"] = tcpScanOutcome.transportComplete
      diagnostics["tcp_responsive_hosts"] = tcpScanOutcome.responsiveHosts.size
      diagnostics["tcp_probe_completed_hosts"] = tcpScanOutcome.completedProbeHosts.size
      val candidateStimulationComplete =
        !tcpScanOutcome.timedOut &&
          tcpScanOutcome.transportComplete &&
          tcpScanOutcome.completedProbeHosts.containsAll(candidateHosts)
      diagnostics["candidate_stimulation_complete"] = candidateStimulationComplete
      diagnostics["tcp_hosts"] = discoveries.size - beforeTcp
      // Some Samsung Family Hub refrigerators advertise Spotify Connect only
      // intermittently.  If the bounded TCP probe finds their documented
      // getInfo endpoint without an mDNS record, ask the endpoint for the
      // manufacturer's own model data.  The port alone never becomes a name.
      enrichKnownProtocolEndpoints(discoveries, socketFactory)
      enrichNetbiosNames(discoveries, socketFactory)

      val currentEvidenceHosts = discoveries.keys.toSet()
      val neighborAfterProbe = readNeighborTable(networkSnapshot.wifiInterfaceName)
      val arpTable = neighborAfterProbe.entries
        .filterKeys { subnetAllowlist.acceptObservation(it) }
      // Android TCP/multicast probes cannot see a sleeping or firewalled IoT
      // device, but a neighbour entry is still a real LAN observation.  Keep
      // that evidence in the private scan payload so the backend can enrich
      // it from the MAC/catalog history instead of dropping the device here.
      // This never creates a product name; identity is resolved server-side.
      val candidateHostSet = candidateHosts.toSet()
      val arpSelection = selectFreshArpObservations(
        beforeProbe = arpBeforeProbe,
        afterProbe = arpTable,
        candidateHosts = candidateHostSet,
        // A response observed during this scan on the captured Wi-Fi is
        // current host-presence evidence. Keep its unchanged interface-scoped
        // neighbour row whether that response came from mDNS, SSDP, ONVIF, or
        // a unicast endpoint; rows with no current response remain suppressed.
        trustedCurrentEvidenceHosts = currentEvidenceHosts,
        // Preserve an unchanged physical neighbour only for a host with an
        // accepted application connection. Refusal/timeout remain coverage
        // telemetry because gateways can synthesize them for unused IPs.
        activelyStimulatedHosts = tcpScanOutcome.activelyStimulatedHosts,
        freshNeighborStateHosts = neighborAfterProbe.freshStateHosts,
        localIp = localIp,
      )
      arpSelection.acceptedHosts
        .forEach { host ->
          val device = getOrCreateObservation(
            discoveries,
            host,
            ObservationPriority.FRESH_NEIGHBOR,
          ) ?: return@forEach
          device.discoverySources.add("android-neighbor")
        }
      diagnostics["arp_entries_after_probe"] = arpTable.size
      diagnostics["arp_observation_hosts"] = arpSelection.acceptedHosts.size
      diagnostics["arp_stale_entries_suppressed"] = arpSelection.suppressedStaleHosts.size
      diagnostics["neighbor_fresh_state_hosts"] = neighborAfterProbe.freshStateHosts.size
      diagnostics["neighbor_unverified_hosts"] = arpSelection.suppressedStaleHosts.size
      diagnostics["neighbor_proc_source_available_after"] = neighborAfterProbe.procSourceAvailable
      diagnostics["neighbor_ip_source_available_after"] = neighborAfterProbe.ipNeighborSourceAvailable
      diagnostics["neighbor_source_available_after"] = neighborAfterProbe.anySourceAvailable
      val neighborProbeComplete =
        neighborBeforeProbe.anySourceAvailable &&
          neighborAfterProbe.anySourceAvailable &&
          candidateStimulationComplete
      val neighborPresenceConfirmed = arpSelection.acceptedHosts.isNotEmpty()
      val neighborCoverageComplete = isNeighborCoverageComplete(
        beforeSourceAvailable = neighborBeforeProbe.anySourceAvailable,
        afterSourceAvailable = neighborAfterProbe.anySourceAvailable,
        beforeEntryCount = arpBeforeProbe.size,
        afterEntryCount = arpTable.size,
        acceptedEntryCount = arpSelection.acceptedHosts.size,
        suppressedEntryCount = arpSelection.suppressedStaleHosts.size,
        candidateStimulationComplete = candidateStimulationComplete,
      )
      diagnostics["neighbor_probe_complete"] = neighborProbeComplete
      diagnostics["neighbor_presence_confirmed"] = neighborPresenceConfirmed
      diagnostics["neighbor_coverage_complete"] = neighborCoverageComplete
      val verifiedArpTable = arpTable.filterKeys { it in arpSelection.acceptedHosts }
      // Defense in depth: no current or future discovery implementation may
      // publish an observation that escaped the common active-subnet gate.
      discoveries.entries.removeAll { (host, _) -> !subnetAllowlist.acceptObservation(host) }
      diagnostics["out_of_subnet_observations_dropped"] = subnetAllowlist.rejectedObservationCount()
      writeNetworkBindingDiagnostics(diagnostics, bindingDiagnostics)
      diagnostics["observation_limit_reached"] = discoveries.capacityExceeded
      diagnostics["observation_overflow_events"] = discoveries.overflowEvents
      diagnostics["observation_hosts_dropped"] = discoveries.droppedHosts
      diagnostics["observation_hosts_evicted"] = discoveries.evictedLowerPriorityHosts
      diagnostics["observation_receive_buffer_dropped"] = discoveries.receiveBufferDrops
      val coverageComplete = scanCoverageComplete(
        candidateCoverageComplete,
        tcpScanOutcome,
        bindingDiagnostics.snapshot().requiresPartialScan,
        discoveries.capacityExceeded,
      )
      diagnostics["coverage_complete"] = coverageComplete
      diagnostics["scan_partial"] = !coverageComplete
      diagnostics["raw_observation_count"] = discoveries.size
      // Aggregate stage counters make it possible to distinguish discovery
      // coverage from identity-evidence loss without logging any address,
      // hostname, MAC value, model text or resident-provided label.
      diagnostics["physical_mac_hosts"] = discoveries.keys.count { verifiedArpTable.containsKey(it) }
      diagnostics["manufacturer_hint_hosts"] = discoveries.values.count {
        !it.manufacturerHint.isNullOrBlank()
      }
      diagnostics["model_hint_hosts"] = discoveries.values.count {
        !it.modelHint.isNullOrBlank()
      }
      Log.i(
        "HomeGuardianScanner",
        scanCompletionLog(System.currentTimeMillis() - started, diagnostics),
      )
      val discoveredDevices = discoveries.values
        .filter { it.ipAddress.isNotBlank() && it.openPorts.isNotEmpty() || it.discoverySources.isNotEmpty() }
        .sortedWith(compareBy<MutableDevice> { riskRank(it) }.thenBy { it.ipAddress })
        .map { it.toPayload(verifiedArpTable[it.ipAddress]) }

      // 자기 자신(이 휴대폰)은 일반 스캔 대상에서 제외되므로 결과 맨 앞에 명시적으로 추가한다.
      val selfDevice = buildSelfDevicePayload(localIp, contextMap, arpTable)
      val devices = listOf(selfDevice) + discoveredDevices.filterNot { (it["ip_address"] as? String) == localIp }

      mapOf(
        "scan_id" to "android-${UUID.randomUUID()}",
        "scan_source" to "android-native",
        "status" to "completed",
        "duration_ms" to (System.currentTimeMillis() - started),
        "network_context" to contextMap,
        "devices_found" to devices.size,
        "scan_diagnostics" to diagnostics,
        "devices" to devices
      )
    } catch (_: Exception) {
      diagnostics["out_of_subnet_observations_dropped"] = subnetAllowlist.rejectedObservationCount()
      writeNetworkBindingDiagnostics(diagnostics, bindingDiagnostics)
      failedScan(
        started,
        contextMap,
        "SCAN_FAILED",
        diagnostics,
      )
    } finally {
      if (multicastLock.isHeld) {
        multicastLock.release()
      }
    }
  }

  private fun writeNetworkBindingDiagnostics(
    target: MutableMap<String, Any?>,
    source: NetworkSocketBindingDiagnostics,
  ) {
    val snapshot = source.snapshot()
    target["wifi_network_socket_binding_required"] = true
    target["wifi_network_socket_bind_attempts"] = snapshot.attempts
    target["wifi_network_socket_bind_failures"] = snapshot.failures
    target["wifi_network_socket_bind_suppressed"] = snapshot.suppressedAfterFailure
    target["wifi_network_unbound_paths_skipped"] = snapshot.unboundPathsSkipped
    target["wifi_network_evidence_path_failures"] = snapshot.evidencePathFailures
    target["wifi_network_socket_binding_complete"] = !snapshot.requiresPartialScan
    if (snapshot.requiresPartialScan) {
      target["scan_partial"] = true
    }
  }

  private fun discoverMdns(
    discoveries: MutableMap<String, MutableDevice>,
    subnetAllowlist: ActiveSubnetAllowlist,
    wifiNetwork: Network,
    socketFactory: WifiBoundSocketFactory,
    bindingDiagnostics: NetworkSocketBindingDiagnostics,
  ) {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
      // Legacy NSD has no per-Network overload. Its results are therefore
      // hints only: a host is adopted only after it answers an mDNS query sent
      // through a socket bound to the captured Wi-Fi Network. A VPN or another
      // interface can contribute a hint, but can never contribute evidence.
      discoverMdnsLegacyHints(
        discoveries,
        subnetAllowlist,
        socketFactory,
        bindingDiagnostics,
      )
      return
    }
    discoverMdnsOnNetwork(discoveries, subnetAllowlist, wifiNetwork, bindingDiagnostics)
  }

  @Suppress("DEPRECATION")
  private fun discoverMdnsLegacyHints(
    discoveries: MutableMap<String, MutableDevice>,
    subnetAllowlist: ActiveSubnetAllowlist,
    socketFactory: WifiBoundSocketFactory,
    bindingDiagnostics: NetworkSocketBindingDiagnostics,
  ) {
    val nsdManager = context.getSystemService(Context.NSD_SERVICE) as? NsdManager ?: return
    val collected = LinkedHashMap<String, NsdServiceInfo>()
    val collectLock = Any()

    mdnsServiceTypes.chunked(MDNS_DISCOVERY_BATCH).forEach { batch ->
      val started = mutableListOf<NsdManager.DiscoveryListener>()
      batch.forEach { serviceType ->
        val listener = object : NsdManager.DiscoveryListener {
          override fun onDiscoveryStarted(regType: String) = Unit

          override fun onServiceFound(serviceInfo: NsdServiceInfo) {
            if (serviceInfo.serviceType == serviceType) {
              synchronized(collectLock) {
                val key = "${serviceInfo.serviceType}|${serviceInfo.serviceName}"
                if (!collected.containsKey(key)) {
                  if (collected.size < MAX_NSD_COLLECTED_SERVICES) {
                    collected[key] = serviceInfo
                  } else {
                    recordReceiveBufferDrop(discoveries)
                  }
                }
              }
            }
          }

          override fun onServiceLost(serviceInfo: NsdServiceInfo) = Unit
          override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) = Unit
          override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) = Unit
          override fun onDiscoveryStopped(serviceType: String) = Unit
        }
        try {
          nsdManager.discoverServices(serviceType, NsdManager.PROTOCOL_DNS_SD, listener)
          started.add(listener)
        } catch (_: Exception) {
          // Another bounded batch and the raw Wi-Fi-bound mDNS pass remain.
        }
      }
      try {
        Thread.sleep(MDNS_LISTEN_WINDOW_MS)
      } catch (_: InterruptedException) {
        Thread.currentThread().interrupt()
      }
      started.forEach { listener ->
        try {
          nsdManager.stopServiceDiscovery(listener)
        } catch (_: Exception) {
          // Some vendor NSD implementations stop failed listeners themselves.
        }
      }
    }

    val collectedSnapshot = synchronized(collectLock) { collected.values.toList() }
    val byType = collectedSnapshot.groupBy { it.serviceType }
    val fairOrder = mutableListOf<NsdServiceInfo>()
    var rank = 0
    while (fairOrder.size < collectedSnapshot.size) {
      var added = false
      byType.values.forEach { group ->
        if (rank < group.size) {
          fairOrder.add(group[rank])
          added = true
        }
      }
      if (!added) break
      rank += 1
    }

    val deadline = System.currentTimeMillis() + MDNS_RESOLVE_BUDGET_MS
    fairOrder.take(MDNS_MAX_RESOLVES).forEach { serviceInfo ->
      if (System.currentTimeMillis() >= deadline) return@forEach
      resolveLegacyMdnsHint(
        nsdManager,
        serviceInfo,
        discoveries,
        subnetAllowlist,
        socketFactory,
        bindingDiagnostics,
      )
    }
  }

  @Suppress("DEPRECATION")
  private fun resolveLegacyMdnsHint(
    nsdManager: NsdManager,
    serviceInfo: NsdServiceInfo,
    discoveries: MutableMap<String, MutableDevice>,
    subnetAllowlist: ActiveSubnetAllowlist,
    socketFactory: WifiBoundSocketFactory,
    bindingDiagnostics: NetworkSocketBindingDiagnostics,
  ) {
    val latch = CountDownLatch(1)
    val resolved = arrayOfNulls<NsdServiceInfo>(1)
    val resolver = object : NsdManager.ResolveListener {
      override fun onResolveFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {
        latch.countDown()
      }

      override fun onServiceResolved(resolvedInfo: NsdServiceInfo) {
        resolved[0] = resolvedInfo
        latch.countDown()
      }
    }

    try {
      nsdManager.resolveService(serviceInfo, resolver)
      if (!latch.await(900, TimeUnit.MILLISECONDS)) return
    } catch (_: Exception) {
      return
    }

    val resolvedInfo = resolved[0] ?: return
    val target = resolvedInfo.host ?: return
    val targetIp = target.hostAddress ?: return
    if (!subnetAllowlist.acceptObservation(targetIp)) {
      bindingDiagnostics.recordUnboundPathSkipped()
      return
    }
    confirmLegacyMdnsHintOnBoundWifi(
      target,
      resolvedInfo.serviceType,
      discoveries,
      subnetAllowlist,
      socketFactory,
    )
  }

  private fun confirmLegacyMdnsHintOnBoundWifi(
    target: InetAddress,
    serviceType: String,
    discoveries: MutableMap<String, MutableDevice>,
    subnetAllowlist: ActiveSubnetAllowlist,
    socketFactory: WifiBoundSocketFactory,
  ) {
    val targetIp = target.hostAddress ?: return
    if (!subnetAllowlist.contains(targetIp)) return
    val normalizedType = serviceType
      .trim()
      .trimEnd('.')
      .removeSuffix(".local")
      .takeIf(String::isNotBlank)
      ?: return
    val query = buildMdnsQuery(listOf("$normalizedType.local"))
    val boundSocket = socketFactory.openDatagram() ?: return
    boundSocket.use { socket ->
      try {
        socket.bind(InetSocketAddress(0))
        socket.connect(InetSocketAddress(target, 5353))
        socket.soTimeout = 300
        repeat(2) {
          socket.send(DatagramPacket(query, query.size))
          val deadline = System.currentTimeMillis() + 350L
          while (System.currentTimeMillis() < deadline) {
            try {
              val buffer = ByteArray(9_000)
              val packet = DatagramPacket(buffer, buffer.size)
              socket.receive(packet)
              if (packet.address?.hostAddress == targetIp) {
                parseMdnsPacket(packet, discoveries, subnetAllowlist)
                return
              }
            } catch (_: java.net.SocketTimeoutException) {
              break
            }
          }
        }
      } catch (_: Exception) {
        // A legacy NSD result is never published without this bound response.
      }
    }
  }

  @RequiresApi(Build.VERSION_CODES.TIRAMISU)
  private fun discoverMdnsOnNetwork(
    discoveries: MutableMap<String, MutableDevice>,
    subnetAllowlist: ActiveSubnetAllowlist,
    wifiNetwork: Network,
    bindingDiagnostics: NetworkSocketBindingDiagnostics,
  ) {
    val nsdManager = context.getSystemService(Context.NSD_SERVICE) as? NsdManager ?: return
    val callbackExecutor = Executor { command -> command.run() }
    // 서비스 타입(30개+)을 '동시에' 탐색한다. 과거엔 타입마다 Thread.sleep(900)+stop 을 '순차로' 돌아
    // 이 단계만 ~36초가 걸렸다(전체 탐색 지연의 1순위). 동일 listener/resolve 로직은 그대로 두고
    // 오케스트레이션만 동시화해 catch 율은 유지하면서 시간을 크게 줄인다. NsdManager 동시 작업 한도를
    // 넘지 않도록 배치 단위(MDNS_DISCOVERY_BATCH)로 나눠 시작하고, 한 배치당 한 번의 listen window 만 쓴다.
    // resolve 는 NSD 동시 한도가 더 엄격하므로(과거엔 1건씩) 모아서 순차로, 총량을 제한해 시간을 가둔다.
    val collected = LinkedHashMap<String, NsdServiceInfo>()  // dedup key = serviceType|serviceName
    val collectLock = Any()

    mdnsServiceTypes.chunked(MDNS_DISCOVERY_BATCH).forEach { batch ->
      val started = mutableListOf<NsdManager.DiscoveryListener>()
      for (serviceType in batch) {
        val listener = object : NsdManager.DiscoveryListener {
          override fun onDiscoveryStarted(regType: String) = Unit
          override fun onServiceFound(serviceInfo: NsdServiceInfo) {
            if (serviceInfo.network != wifiNetwork) {
              // Even a same-CIDR service from a VPN/secondary interface must
              // never enter the collected set.
              bindingDiagnostics.recordUnboundPathSkipped()
              return
            }
            if (serviceInfo.serviceType == serviceType) {
              synchronized(collectLock) {
                val key = "${serviceInfo.serviceType}|${serviceInfo.serviceName}"
                if (!collected.containsKey(key)) {
                  if (collected.size < MAX_NSD_COLLECTED_SERVICES) {
                    collected[key] = serviceInfo
                  } else {
                    recordReceiveBufferDrop(discoveries)
                  }
                }
              }
            }
          }
          override fun onServiceLost(serviceInfo: NsdServiceInfo) = Unit
          override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) = Unit
          override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) = Unit
          override fun onDiscoveryStopped(serviceType: String) = Unit
        }
        try {
          nsdManager.discoverServices(
            serviceType,
            NsdManager.PROTOCOL_DNS_SD,
            wifiNetwork,
            callbackExecutor,
            listener,
          )
          started.add(listener)
        } catch (_: Exception) {
          // 동시 한도 초과/일시 오류 — 이 타입만 건너뛴다(비치명, 다음 배치/raw mDNS 가 보완).
        }
      }
      try {
        Thread.sleep(MDNS_LISTEN_WINDOW_MS)
      } catch (_: InterruptedException) {
        // 무시: 곧바로 stop 으로 정리한다.
      }
      started.forEach { listener ->
        try {
          nsdManager.stopServiceDiscovery(listener)
        } catch (_: Exception) {
          // Discovery can already be stopped on some Android versions.
        }
      }
    }

    // 타입 편향 방지: 타입별로 묶어 라운드로빈으로 펼친다(초반 배치 타입이 resolve 예산을 독식해
    // 후순위 타입 _hue/_nanoleaf/_printer 가 굶는 것을 막는다). 각 타입의 1번째 인스턴스를 모두 먼저
    // resolve 한 뒤 2번째로 넘어간다. 총량 상한(MDNS_MAX_RESOLVES) + 벽시계 예산(MDNS_RESOLVE_BUDGET_MS)
    // 으로 시간도 가둔다(실패 resolve 가 latch 900ms 씩 쌓여 전체가 늘어지는 것 방지).
    val toResolve = synchronized(collectLock) { collected.values.toList() }
    val byType = toResolve.groupBy { it.serviceType }
    val fairOrder = mutableListOf<NsdServiceInfo>()
    var rank = 0
    while (fairOrder.size < toResolve.size) {
      var addedThisRank = false
      for (group in byType.values) {
        if (rank < group.size) {
          fairOrder.add(group[rank])
          addedThisRank = true
        }
      }
      if (!addedThisRank) break
      rank++
    }
    val resolveDeadline = System.currentTimeMillis() + MDNS_RESOLVE_BUDGET_MS
    for (serviceInfo in fairOrder.take(MDNS_MAX_RESOLVES)) {
      if (System.currentTimeMillis() > resolveDeadline) break
      resolveMdnsService(
        nsdManager,
        serviceInfo,
        discoveries,
        subnetAllowlist,
        wifiNetwork,
        bindingDiagnostics,
      )
    }
  }

  // 원시 mDNS 질의(UDP 멀티캐스트 224.0.0.251:5353) — NsdManager 보조 채널.
  // NsdManager(안드로이드 mDNS)가 불안정해 mDNS 만 광고하는 기기(냉장고 등)를 자주 놓치므로,
  // PTR 질의를 직접 보내고 더 길게 들어 catch 율을 높인다. 응답에 여러 기기의 레코드가 함께
  // 들어올 수 있으므로 UDP 출처 IP 하나에 전부 합치지 않고 PTR -> SRV -> A/AAAA 관계를 따라
  // 서비스 증거를 실제 호스트 주소에 귀속한다. 멀티캐스트락은 호출부에서 이미 잡고 있다.
  private fun discoverMdnsRaw(
    discoveries: MutableMap<String, MutableDevice>,
    subnetAllowlist: ActiveSubnetAllowlist,
    socketFactory: WifiBoundSocketFactory,
    wifiInterfaceName: String?,
    bindingDiagnostics: NetworkSocketBindingDiagnostics,
  ) {
    val group = try { InetAddress.getByName("224.0.0.251") } catch (_: Exception) { return }
    val wifiInterface = try {
      wifiInterfaceName
        ?.takeIf(String::isNotBlank)
        ?.let(NetworkInterface::getByName)
    } catch (_: Exception) {
      null
    }
    if (wifiInterface == null) {
      // joinGroup(group) without an explicit interface can silently use a VPN
      // or another same-CIDR NIC. Skip raw mDNS instead of taking that route.
      bindingDiagnostics.recordEvidencePathFailure()
      return
    }
    // One giant PTR packet is frequently dropped by home routers once it
    // exceeds the classic 512-byte DNS UDP limit.  Send small batches so a
    // busy LAN does not lose an entire class of devices (printers, lights,
    // speakers, cameras) at once.
    val queryNames = (mdnsServiceTypes.map { it.trimEnd('.') + ".local" } + listOf("_services._dns-sd._udp.local"))
      .distinct()
    val queries = queryNames.chunked(8).map(::buildMdnsQuery)
    val dynamicServiceTypes = linkedSetOf<String>()
    try {
      val boundSocket = socketFactory.openMulticast() ?: return
      boundSocket.use { socket ->
        socket.reuseAddress = true
        socket.bind(InetSocketAddress(5353))
        socket.soTimeout = 400
        try {
          socket.joinGroup(InetSocketAddress(group, 5353), wifiInterface)
        } catch (_: Exception) {
          bindingDiagnostics.recordEvidencePathFailure()
          return@use
        }
        repeat(2) {
          queries.forEach { query ->
            try { socket.send(DatagramPacket(query, query.size, group, 5353)) } catch (_: Exception) {}
          }
          val deadline = System.currentTimeMillis() + 1_200
          val buffer = ByteArray(9000)
          while (System.currentTimeMillis() < deadline) {
            try {
              val packet = DatagramPacket(buffer, buffer.size)
              socket.receive(packet)
              val remainingDynamicTypes =
                (MDNS_MAX_DYNAMIC_SERVICE_TYPES - dynamicServiceTypes.size).coerceAtLeast(0)
              if (remainingDynamicTypes > 0) {
                parseDnsSdServiceTypes(packet.data.copyOf(packet.length), remainingDynamicTypes)
                  .filterNot(queryNames::contains)
                  .forEach(dynamicServiceTypes::add)
              }
              parseMdnsPacket(packet, discoveries, subnetAllowlist)
            } catch (_: java.net.SocketTimeoutException) {
              // deadline 까지 계속 수신 시도
            } catch (_: Exception) {
              return@repeat
            }
          }
        }
        // Query newly advertised base service types once. Do not recursively
        // expand types found in the follow-up responses: the meta-query above
        // is the only authority for this bounded dynamic pass.
        val dynamicQueries = dynamicServiceTypes
          .take(MDNS_MAX_DYNAMIC_SERVICE_TYPES)
          .chunked(8)
          .map(::buildMdnsQuery)
        if (dynamicQueries.isNotEmpty()) {
          dynamicQueries.forEach { query ->
            try { socket.send(DatagramPacket(query, query.size, group, 5353)) } catch (_: Exception) {}
          }
          val dynamicDeadline = System.currentTimeMillis() + MDNS_DYNAMIC_QUERY_BUDGET_MS
          val dynamicBuffer = ByteArray(9_000)
          while (System.currentTimeMillis() < dynamicDeadline) {
            try {
              val packet = DatagramPacket(dynamicBuffer, dynamicBuffer.size)
              socket.receive(packet)
              parseMdnsPacket(packet, discoveries, subnetAllowlist)
            } catch (_: java.net.SocketTimeoutException) {
              // Continue until the bounded follow-up window closes.
            } catch (_: Exception) {
              break
            }
          }
        }
        try {
          socket.leaveGroup(InetSocketAddress(group, 5353), wifiInterface)
        } catch (_: Exception) {
          // Socket close below is sufficient cleanup after a failed leave.
        }
      }
    } catch (_: Exception) {
      bindingDiagnostics.recordEvidencePathFailure()
      // 멀티캐스트 미지원/포트 점유 등 — 비치명. NsdManager 결과로 폴백.
    }
  }

  private fun buildMdnsQuery(names: List<String>): ByteArray {
    val out = java.io.ByteArrayOutputStream()
    val count = names.size
    out.write(byteArrayOf(0, 0, 0, 0, (count ushr 8).toByte(), count.toByte(), 0, 0, 0, 0, 0, 0))
    for (name in names) {
      for (label in name.split(".")) {
        if (label.isEmpty()) continue
        val bytes = label.toByteArray(Charset.forName("UTF-8"))
        out.write(bytes.size and 0x3F)
        out.write(bytes)
      }
      out.write(0)
      out.write(byteArrayOf(0, 12))               // QTYPE PTR
      out.write(byteArrayOf(0x80.toByte(), 1))    // QCLASS: QU 비트(유니캐스트 응답 요청) + IN
    }
    return out.toByteArray()
  }

  // DNS 이름 읽기(압축 포인터 0xC0 지원). 반환: (이름, 압축 점프 전 다음 오프셋)
  private fun readDnsName(data: ByteArray, start: Int): Pair<String, Int> {
    val labels = mutableListOf<String>()
    var offset = start
    var next = -1
    var guard = 0
    while (offset in 0 until data.size && guard++ < 128) {
      val len = data[offset].toInt() and 0xFF
      if (len == 0) { offset += 1; break }
      if (len and 0xC0 == 0xC0) {
        if (offset + 1 >= data.size) break
        val pointer = ((len and 0x3F) shl 8) or (data[offset + 1].toInt() and 0xFF)
        if (next == -1) next = offset + 2
        offset = pointer
        continue
      }
      if (offset + 1 + len > data.size) break
      labels.add(String(data, offset + 1, len, Charset.forName("UTF-8")))
      offset += 1 + len
    }
    return labels.joinToString(".") to (if (next != -1) next else offset)
  }

  private fun parseMdnsPacket(
    packet: DatagramPacket,
    discoveries: MutableMap<String, MutableDevice>,
    subnetAllowlist: ActiveSubnetAllowlist,
  ) {
    val src = packet.address?.hostAddress ?: return
    if (!subnetAllowlist.acceptObservation(src)) return
    val data = packet.data.copyOf(packet.length)
    parseMdnsAttributions(data, src).forEach { attribution ->
      // UDP source뿐 아니라 A/AAAA로 얻은 최종 주소도 현재 Wi-Fi subnet에 속해야 한다.
      if (!subnetAllowlist.acceptObservation(attribution.ipAddress)) return@forEach

      val device = getOrCreateObservation(
        discoveries,
        attribution.ipAddress,
        ObservationPriority.STRUCTURED_DISCOVERY,
      ) ?: return@forEach
      device.discoverySources.add("mdns")
      attribution.ports.forEach(device.openPorts::add)
      attribution.fingerprints.forEach { fingerprint ->
        device.fingerprints.add(fingerprint)
        applyDiscoveryHints(device, fingerprint.substringAfter(":"))
      }

      // spotify-connect 를 raw 로 잡았으면 getInfo 보조용 endpoint 도 기록(enrichSpotifyConnect 사용).
      if (attribution.ports.isNotEmpty() &&
        attribution.fingerprints.any { it.contains("spotify-connect", ignoreCase = true) } &&
        device.fingerprints.none { it.startsWith("spotify-endpoint:") }
      ) {
        val cpath = attribution.fingerprints
          .firstOrNull { it.startsWith("mdns-txt:", ignoreCase = true) && it.contains("CPath=", ignoreCase = true) }
          ?.substringAfter("CPath=", "")?.trim() ?: ""
        device.fingerprints.add("spotify-endpoint:${attribution.ipAddress}|${attribution.ports.first()}|$cpath")
      }
    }
  }

  // SMB(139/445) 가 열렸지만 이름이 없는 기기(주로 PC)에 NetBIOS Node Status(UDP 137) 질의로
  // 실제 컴퓨터 이름을 붙인다. 이름이 없던 곳에 '추가만' 하므로 회귀 위험이 낮다(응답 없으면 그대로).
  private fun enrichNetbiosNames(
    discoveries: MutableMap<String, MutableDevice>,
    socketFactory: WifiBoundSocketFactory,
  ) {
    discoveries.values.forEach { device ->
      if (device.nameHint == null && (device.openPorts.contains(445) || device.openPorts.contains(139))) {
        val name = queryNetbiosName(device.ipAddress, socketFactory)
        if (name != null) {
          device.promoteObservationPriority(ObservationPriority.STRUCTURED_DISCOVERY)
          device.nameHint = name
          device.discoverySources.add("netbios")
          device.fingerprints.add("netbios-name:$name")
          applyDiscoveryHints(device, name)
        }
      }
    }
  }

  private fun queryNetbiosName(host: String, socketFactory: WifiBoundSocketFactory): String? {
    return try {
      val out = java.io.ByteArrayOutputStream()
      // 헤더: txid=0x1337, flags=0, qd=1, an/ns/ar=0
      out.write(byteArrayOf(0x13, 0x37, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0))
      // 질문 이름: "*" 와일드카드의 NetBIOS 1차 인코딩(길이 0x20 + 32바이트 + 0x00)
      out.write(0x20)
      out.write("CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".toByteArray(Charset.forName("US-ASCII")))
      out.write(0)
      out.write(byteArrayOf(0, 0x21))  // QTYPE NBSTAT
      out.write(byteArrayOf(0, 1))     // QCLASS IN
      val req = out.toByteArray()
      val boundSocket = socketFactory.openDatagram() ?: return null
      boundSocket.use { socket ->
        socket.bind(InetSocketAddress(0))
        socket.soTimeout = 700
        val target = InetAddress.getByName(host)
        // UDP 는 유실이 잦다. NBSTAT 를 최대 3회 재시도해 한 번이라도 응답하면 이름을 얻는다.
        // 단발 질의는 실제로 응답하는 PC(예: DESKTOP-HOME)도 패킷 유실/지연으로 놓칠 수 있다.
        // 이름 '추가만' 하므로 모두 실패해도 기존과 동일(null) — 회귀 위험 없음.
        repeat(3) {
          try {
            socket.send(DatagramPacket(req, req.size, target, 137))
            val buffer = ByteArray(2048)
            val packet = DatagramPacket(buffer, buffer.size)
            socket.receive(packet)
            val name = parseNetbiosResponse(packet.data, packet.length)
            if (name != null) return@use name
          } catch (_: java.net.SocketTimeoutException) {
            // 타임아웃 → 다음 재시도
          }
        }
        null
      }
    } catch (_: Exception) {
      null
    }
  }

  private fun parseNetbiosResponse(data: ByteArray, length: Int): String? {
    return try {
      if (length < 12) return null
      // 응답이 질문을 에코할 수도(QDCOUNT=1) 안 할 수도(0) 있으므로 헤더를 읽어 견고하게 처리한다.
      val qd = ((data[4].toInt() and 0xFF) shl 8) or (data[5].toInt() and 0xFF)
      val an = ((data[6].toInt() and 0xFF) shl 8) or (data[7].toInt() and 0xFF)
      if (an < 1) return null
      var offset = 12
      repeat(qd) {
        val (_, o) = readDnsName(data, offset); offset = o + 4  // 이름 + qtype(2) + qclass(2)
      }
      // 답변 RR 이름(NetBIOS 인코딩 이름 또는 압축 포인터) → readDnsName 으로 견고하게 스킵
      val (_, afterName) = readDnsName(data, offset); offset = afterName
      offset += 2 + 2 + 4 + 2  // type(2) class(2) ttl(4) rdlen(2)
      if (offset >= length) return null
      val numNames = data[offset].toInt() and 0xFF
      offset += 1
      for (n in 0 until numNames) {
        if (offset + 18 > length) break
        val nameBytes = data.copyOfRange(offset, offset + 15)
        val suffix = data[offset + 15].toInt() and 0xFF
        val flags = ((data[offset + 16].toInt() and 0xFF) shl 8) or (data[offset + 17].toInt() and 0xFF)
        val isGroup = (flags and 0x8000) != 0
        offset += 18
        val name = String(nameBytes, Charset.forName("US-ASCII")).trim()
        // 유니크(비그룹) 워크스테이션(0x00)/서버(0x20) 이름 = 컴퓨터 이름
        if (!isGroup && (suffix == 0x00 || suffix == 0x20) && name.isNotBlank()) {
          return name
        }
      }
      null
    } catch (_: Exception) {
      null
    }
  }

  @RequiresApi(Build.VERSION_CODES.TIRAMISU)
  private fun resolveMdnsService(
    nsdManager: NsdManager,
    serviceInfo: NsdServiceInfo,
    discoveries: MutableMap<String, MutableDevice>,
    subnetAllowlist: ActiveSubnetAllowlist,
    wifiNetwork: Network,
    bindingDiagnostics: NetworkSocketBindingDiagnostics,
  ) {
    if (serviceInfo.network != wifiNetwork) {
      bindingDiagnostics.recordUnboundPathSkipped()
      return
    }
    val latch = CountDownLatch(1)
    val resolver = object : NsdManager.ResolveListener {
      override fun onResolveFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {
        latch.countDown()
      }

      override fun onServiceResolved(resolvedInfo: NsdServiceInfo) {
        if (resolvedInfo.network != wifiNetwork) {
          bindingDiagnostics.recordUnboundPathSkipped()
          latch.countDown()
          return
        }
        val ip = resolvedInfo.host?.hostAddress
        if (subnetAllowlist.acceptObservation(ip)) {
          checkNotNull(ip)
          val device = getOrCreateObservation(
            discoveries,
            ip,
            ObservationPriority.STRUCTURED_DISCOVERY,
          ) ?: run {
            latch.countDown()
            return
          }
          device.discoverySources.add("mdns")
          device.services.add(mdnsServiceName(resolvedInfo.serviceType))
          if (resolvedInfo.port in 1..65535) {
            device.openPorts.add(resolvedInfo.port)
          }
          device.fingerprints.add("mdns-type:${resolvedInfo.serviceType}")
          device.fingerprints.add("mdns-name:${resolvedInfo.serviceName}")
          // mDNS TXT 레코드 수집: 가전/IoT 가 제조사·모델·친근한 이름을 TXT 로 광고하는 경우가 많다.
          // 특정 IP/MAC 하드코딩 없이, 기기가 스스로 알리는 정보로 식별한다(예: Samsung FamilyHub).
          resolvedInfo.attributes?.forEach { (key, value) ->
            val text = value?.let { String(it, Charset.forName("UTF-8")) } ?: ""
            device.fingerprints.add("mdns-txt:$key=$text")
            applyDiscoveryHints(device, "$key $text")
          }
          applyDiscoveryHints(device, "${resolvedInfo.serviceType} ${resolvedInfo.serviceName}")
          // Spotify Connect: 제조사·모델은 mDNS TXT 가 아니라 ZeroConf getInfo HTTP 응답에 들어 있다.
          // 여기선 호출 위치(ip|port|CPath)만 기록하고, 실제 getInfo 는 resolve latch 를 막지 않도록
          // 별도 패스(enrichSpotifyConnect)에서 짧은 타임아웃으로 호출한다. CPath 는 TXT 광고값(없으면 빈값).
          if (resolvedInfo.serviceType.contains("spotify-connect", ignoreCase = true) &&
            resolvedInfo.port in 1..65535
          ) {
            val cpath = resolvedInfo.attributes
              ?.entries?.firstOrNull { it.key.equals("CPath", ignoreCase = true) }
              ?.value?.let { String(it, Charset.forName("UTF-8")) }
              ?.takeIf { it.isNotBlank() } ?: ""
            device.fingerprints.add("spotify-endpoint:$ip|${resolvedInfo.port}|$cpath")
          }
        }
        latch.countDown()
      }
    }

    try {
      nsdManager.resolveService(serviceInfo, resolver)
      latch.await(900, TimeUnit.MILLISECONDS)
    } catch (_: Exception) {
      // Android NSD allows only limited concurrent resolves; failed resolves are non-fatal.
    }
  }

  private fun buildNetworkSnapshot(wifiManager: WifiManager): NetworkSnapshot {
    val connectivity = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    val network = connectivity.activeNetwork
    val capabilities = network?.let { connectivity.getNetworkCapabilities(it) }
    val isWifi = capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
    val linkProperties = network
      ?.takeIf { isWifi }
      ?.let(connectivity::getLinkProperties)
    val reportedInterfaceName = linkProperties?.interfaceName?.takeIf(String::isNotBlank)
    val connectionInfo = wifiManager.connectionInfo
    val reportedWifiIp = intToIp(connectionInfo.ipAddress)
    val capturedLinkAddresses = linkProperties
      ?.linkAddresses
      ?.mapNotNull { linkAddress ->
        val address = linkAddress.address as? Inet4Address ?: return@mapNotNull null
        address.hostAddress?.let { CapturedIpv4LinkAddress(it, linkAddress.prefixLength) }
      }
      .orEmpty()
    val linkSubnet = selectLinkPropertiesWifiSubnet(capturedLinkAddresses, reportedWifiIp)
    val hasUsableCapturedLinkAddress = hasUsableLinkPropertiesWifiAddress(capturedLinkAddresses)

    // LinkProperties is authoritative. DHCP is consulted only when Android did
    // not expose any usable IPv4 LinkAddress, and that fallback must validate
    // both possible netmask byte orders against the local IP and gateway.
    val dhcpFallback = if (linkSubnet == null && !hasUsableCapturedLinkAddress && isWifi) {
      val dhcpInfo = wifiManager.dhcpInfo
      validatedDhcpWifiSubnet(
        localIp = intToIp(connectionInfo.ipAddress),
        gatewayIp = intToIp(dhcpInfo.gateway),
        rawNetmask = dhcpInfo.netmask,
      )
    } else {
      null
    }
    val authoritativeSubnet = linkSubnet ?: dhcpFallback
    val localIp = authoritativeSubnet?.localIp
    val subnet = authoritativeSubnet?.subnetCidr
    // Some Android 11 builds expose LinkProperties without an interface name
    // even though the active Wi-Fi IPv4 address is available. Resolve the
    // interface from that address so ARP/ip-neigh rows are still restricted to
    // the currently connected Wi-Fi instead of being discarded as unknown.
    val wifiInterfaceName = reportedInterfaceName
      ?: findNetworkInterfaceForIpv4(localIp ?: reportedWifiIp)
    val gatewayIp = linkProperties
      ?.routes
      ?.asSequence()
      ?.filter { it.isDefaultRoute }
      ?.mapNotNull { (it.gateway as? Inet4Address)?.hostAddress }
      ?.firstOrNull { candidate -> subnet != null && ipv4HostBelongsToCidr(candidate, subnet) }
      ?: if (authoritativeSubnet?.source == "validated-dhcp-fallback") {
        authoritativeSubnet.gatewayIp
      } else {
        null
      }
    val emulatorReason = emulatorReason()
    val virtualReason = virtualNetworkReason(localIp, gatewayIp, subnet, emulatorReason)

    return NetworkSnapshot(
      context = mapOf(
        "ssid" to cleanSsid(connectionInfo.ssid),
        "bssid" to connectionInfo.bssid,
        "local_ip" to localIp,
        "gateway_ip" to gatewayIp,
        "subnet_cidr" to subnet,
        "subnet_source" to authoritativeSubnet?.source,
        "is_private_network" to (localIp?.let { isPrivateIpv4(it) } == true),
        "interface_type" to if (isWifi) "wifi" else "unknown",
        "is_emulator" to (emulatorReason != null),
        "is_virtual_network" to (virtualReason != null),
        "virtual_network_reason" to virtualReason,
      ),
      wifiNetwork = network?.takeIf { isWifi },
      wifiInterfaceName = wifiInterfaceName,
    )
  }

  private fun findNetworkInterfaceForIpv4(localIp: String?): String? {
    val target = localIp?.trim()?.takeIf { it.isNotEmpty() } ?: return null
    return try {
      NetworkInterface.getNetworkInterfaces()
        ?.toList()
        ?.firstOrNull { networkInterface ->
          !networkInterface.isLoopback &&
            networkInterface.inetAddresses.toList().any { address ->
              address is Inet4Address && address.hostAddress == target
            }
        }
        ?.name
    } catch (_: Exception) {
      null
    }
  }

  private fun discoverSsdp(
    discoveries: MutableMap<String, MutableDevice>,
    subnetAllowlist: ActiveSubnetAllowlist,
    socketFactory: WifiBoundSocketFactory,
  ) {
    val request = """
      M-SEARCH * HTTP/1.1
      HOST: 239.255.255.250:1900
      MAN: "ssdp:discover"
      MX: 2
      ST: ssdp:all

    """.trimIndent().replace("\n", "\r\n").toByteArray(Charset.forName("UTF-8"))

    val boundSocket = socketFactory.openDatagram() ?: return
    boundSocket.use { socket ->
      socket.bind(InetSocketAddress(0))
      socket.soTimeout = 500
      repeat(2) {
        try {
          socket.send(DatagramPacket(request, request.size, InetAddress.getByName("239.255.255.250"), 1900))
        } catch (_: Exception) {
          return@repeat
        }
        val deadline = System.currentTimeMillis() + 1_500
        while (System.currentTimeMillis() < deadline) {
          try {
            val buffer = ByteArray(4096)
            val packet = DatagramPacket(buffer, buffer.size)
            socket.receive(packet)
            val ip = packet.address.hostAddress ?: continue
            if (!subnetAllowlist.acceptObservation(ip)) continue
            val response = String(packet.data, 0, packet.length)
            val headers = parseHeaders(response)
            val device = getOrCreateObservation(
              discoveries,
              ip,
              ObservationPriority.STRUCTURED_DISCOVERY,
            ) ?: continue
            device.discoverySources.add("ssdp")
            device.services.add("upnp")
            device.openPorts.add(1900)
            boundedEvidenceFingerprint("ssdp-server", headers["server"])
              ?.let(device.fingerprints::add)
            boundedEvidenceFingerprint("ssdp-st", headers["st"])
              ?.let(device.fingerprints::add)
            boundedProtocolIdentityFingerprint("ssdp-usn", headers["usn"])
              ?.let(device.fingerprints::add)
            headers["location"]
              ?.takeIf { location ->
                sameIpv4Endpoint(subnetAllowlist.resolveAllowedHttpHost(location), ip)
              }
              ?.let { boundedEvidenceFingerprint("ssdp-location", it, maxValueChars = 512) }
              ?.let(device.fingerprints::add)
            // SSDP Server is a software banner, not a product name/model.  ST
            // carries the protocol category and is the only header used for a
            // discovery hint here.
            headers["st"]?.let { applyDiscoveryHints(device, it) }
          } catch (_: Exception) {
            break
          }
        }
      }
    }
  }

  private fun discoverOnvif(
    discoveries: MutableMap<String, MutableDevice>,
    subnetAllowlist: ActiveSubnetAllowlist,
    socketFactory: WifiBoundSocketFactory,
  ) {
    val probe = """
      <?xml version="1.0" encoding="UTF-8"?>
      <e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
        xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
        xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
        xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
        <e:Header>
          <w:MessageID>uuid:${UUID.randomUUID()}</w:MessageID>
          <w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
          <w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
        </e:Header>
        <e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body>
      </e:Envelope>
    """.trimIndent().toByteArray(Charset.forName("UTF-8"))

    val boundSocket = socketFactory.openMulticast() ?: return
    boundSocket.use { socket ->
      socket.bind(InetSocketAddress(0))
      socket.soTimeout = 500
      repeat(2) {
        try {
          socket.send(DatagramPacket(probe, probe.size, InetAddress.getByName("239.255.255.250"), 3702))
        } catch (_: Exception) {
          return@repeat
        }
        val deadline = System.currentTimeMillis() + 1_500
        while (System.currentTimeMillis() < deadline) {
          try {
            val buffer = ByteArray(8192)
            val packet = DatagramPacket(buffer, buffer.size)
            socket.receive(packet)
            val ip = packet.address.hostAddress ?: continue
            if (!subnetAllowlist.acceptObservation(ip)) continue
            val response = String(packet.data, 0, packet.length)
            val device = getOrCreateObservation(
              discoveries,
              ip,
              ObservationPriority.STRUCTURED_DISCOVERY,
            ) ?: continue
            device.discoverySources.add("ws-discovery")
            device.services.add("onvif")
            device.openPorts.add(3702)
            device.fingerprints.add("onvif-ws-discovery")
            applyDiscoveryHints(device, response)
          } catch (_: Exception) {
            break
          }
        }
      }
    }
  }

  private fun scanTcpPorts(
    hosts: List<String>,
    ports: List<Int>,
    timeoutMillis: Int,
    discoveries: MutableMap<String, MutableDevice>,
    socketFactory: WifiBoundSocketFactory,
  ): TcpScanOutcome {
    // 호스트 하나의 포트를 순차로 기다리면 Wi-Fi 격리망에서 253개 주소 ×
    // 20여 포트의 timeout이 누적되어, 뒤쪽 주소가 검사 예산에서 잘린다.
    // host/port 쌍을 bounded pool로 병렬화하고 port-major 순서로 제출해
    // 첫 번째 대표 포트가 모든 주소를 한 번씩 돈 뒤 다음 포트로 넘어간다.
    // 이 순서가 아니면 큰 CIDR에서 앞쪽 host가 모든 포트를 독식하고 뒤쪽
    // host는 45초 예산 전에 한 번도 검사되지 않는다.
    val executor = Executors.newFixedThreadPool(128)
    val deadline = System.currentTimeMillis() + TCP_SCAN_BUDGET_MS
    var timedOut = false
    var transportComplete = true
    val responsiveHosts = linkedSetOf<String>()
    val completedProbeHosts = linkedSetOf<String>()
    val activelyStimulatedHosts = linkedSetOf<String>()
    val refusedHosts = linkedSetOf<String>()
    try {
      val tasks = buildFairTcpProbeTargets(hosts, ports).map { target ->
        Callable {
          probeTcpEndpoint(target.host, target.port, timeoutMillis, socketFactory)
        }
      }
      val remainingMillis = (deadline - System.currentTimeMillis()).coerceAtLeast(1L)
      executor.invokeAll(tasks, remainingMillis, TimeUnit.MILLISECONDS).forEach { future ->
        if (future.isCancelled) {
          timedOut = true
          return@forEach
        }
        val result = try {
          future.get()
        } catch (_: Exception) {
          transportComplete = false
          return@forEach
        }
        completedProbeHosts.add(result.host)
        // Transport completion includes timeouts, unreachable errors and
        // connection refusals. A gateway can synthesize those negatives for
        // unused addresses, so only an accepted application connection may
        // refresh an otherwise unchanged neighbour row.
        if (tcpProbeConfirmsDevicePresence(result)) activelyStimulatedHosts.add(result.host)
        transportComplete = recordTcpEndpointProbe(
          result,
          discoveries,
          responsiveHosts,
          refusedHosts,
        ) && transportComplete
      }
      // Banner/body enrichment is intentionally a second, small pass over
      // responsive hosts.  It must not consume connect slots for all empty
      // addresses and it remains bounded by the same deadline.
      discoveries.values
        .filter { it.discoverySources.contains("tcp-port-probe") }
        .forEach { device ->
          if (System.currentTimeMillis() + 500L >= deadline) {
            timedOut = true
            return@forEach
          }
          for (port in device.openPorts) {
            if (System.currentTimeMillis() + 500L >= deadline) {
              timedOut = true
              break
            }
            if (port == 80 || port == 8080 || port == 8888 || port == 5000 || port == 9761) {
              httpServerBanner(device.ipAddress, port, timeoutMillis, socketFactory)?.let {
                applyHttpBanner(device, it)
              }
            }
          }
        }
      if (System.currentTimeMillis() >= deadline) timedOut = true
    } finally {
      executor.shutdownNow()
      try {
        executor.awaitTermination(2, TimeUnit.SECONDS)
      } catch (_: InterruptedException) {
        Thread.currentThread().interrupt()
      }
    }
    return TcpScanOutcome(
      timedOut = timedOut,
      responsiveHosts = responsiveHosts,
      transportComplete = transportComplete,
      completedProbeHosts = completedProbeHosts,
      activelyStimulatedHosts = activelyStimulatedHosts,
    )
  }

  /**
   * 디바이스의 HTTP 응답에서 Server / WWW-Authenticate / X-Powered-By 헤더를 받는다.
   * 펌웨어 버전 추정에 사용. 응답 없으면 null.
   */
  private fun httpServerBanner(
    host: String,
    port: Int,
    timeoutMillis: Int,
    socketFactory: WifiBoundSocketFactory,
  ): Map<String, String>? {
    // 일부 임베디드 웹서버(공유기·카메라·NAS)는 HEAD 요청을 거부하거나 헤더를 안 준다.
    // HEAD 로 Server/인증 헤더를 못 얻으면 GET 으로 한 번 더 시도한다(추가만 → 식별 누락 감소).
    for (method in listOf("HEAD", "GET")) {
      val headers = httpRequestHeaders(host, port, method, timeoutMillis, socketFactory)
      if (headers != null &&
        (headers.containsKey("server") || headers.containsKey("www-authenticate") || headers.containsKey("x-powered-by"))
      ) {
        return headers
      }
    }
    return null
  }

  private fun httpRequestHeaders(
    host: String,
    port: Int,
    method: String,
    timeoutMillis: Int,
    socketFactory: WifiBoundSocketFactory,
  ): Map<String, String>? {
    return try {
      val boundSocket = socketFactory.openStream() ?: return null
      boundSocket.use { socket ->
        socket.connect(InetSocketAddress(host, port), timeoutMillis)
        socket.soTimeout = timeoutMillis * 3
        val request = "$method / HTTP/1.0\r\nHost: $host\r\nUser-Agent: HomeGuardian/0.2\r\nAccept: */*\r\n\r\n"
        socket.getOutputStream().write(request.toByteArray(Charset.forName("UTF-8")))
        socket.getOutputStream().flush()
        val buffer = ByteArray(4096)
        val read = socket.getInputStream().read(buffer)
        if (read <= 0) return null
        parseHttpHeaders(String(buffer, 0, read, Charset.forName("UTF-8")))
      }
    } catch (_: Exception) {
      null
    }
  }

  private fun parseHttpHeaders(response: String): Map<String, String> {
    val headers = mutableMapOf<String, String>()
    val lines = response.split("\r\n", "\n")
    for (line in lines.drop(1)) {
      if (line.isBlank()) break
      val colon = line.indexOf(":")
      if (colon <= 0) continue
      val key = line.substring(0, colon).trim().lowercase()
      val value = line.substring(colon + 1).trim()
      if (value.isNotEmpty()) {
        headers[key] = value
      }
    }
    return headers
  }

  private fun applyHttpBanner(device: MutableDevice, headers: Map<String, String>) {
    val server = headers["server"]
    val realm = headers["www-authenticate"]
    val poweredBy = headers["x-powered-by"]
    if (!server.isNullOrBlank()) {
      device.fingerprints.add("http-server:$server")
      // A Server header is private firmware/CVE evidence only.  It must never
      // become modelHint, nameHint, manufacturerHint, or a type hint.
      device.firmwareHint = extractFirmwareToken(server) ?: device.firmwareHint
    }
    if (!realm.isNullOrBlank()) {
      device.fingerprints.add("http-realm:$realm")
    }
    if (!poweredBy.isNullOrBlank()) {
      device.fingerprints.add("http-powered-by:$poweredBy")
      device.firmwareHint = extractFirmwareToken(poweredBy) ?: device.firmwareHint
    }
  }

  /** "Server: foo/1.2.3" 같은 banner 에서 "1.2.3" 부분 추출 */
  private fun extractFirmwareToken(text: String): String? {
    val match = Regex("([A-Za-z][A-Za-z0-9._-]*)/(\\d+(?:\\.\\d+){0,3}(?:[A-Za-z0-9_-]*)?)")
      .find(text)
    return if (match != null) "${match.groupValues[1]} ${match.groupValues[2]}" else null
  }

  private fun probeTcpEndpoint(
    host: String,
    port: Int,
    timeoutMillis: Int,
    socketFactory: WifiBoundSocketFactory,
  ): TcpEndpointProbe {
    return try {
      val boundSocket = socketFactory.openStream()
        ?: return TcpEndpointProbe(
          host,
          port,
          TcpEndpointState.NO_RESPONSE,
          transportComplete = false,
        )
      boundSocket.use { socket ->
        socket.connect(InetSocketAddress(host, port), timeoutMillis)
        TcpEndpointProbe(host, port, TcpEndpointState.OPEN)
      }
    } catch (error: Exception) {
      classifyTcpEndpointFailure(host, port, error)
    }
  }

  private fun readNeighborTable(expectedInterface: String?): NeighborTableSnapshot {
    // Android 11 vendor builds may omit /proc/net/arp entirely. Read it
    // independently so that its absence never prevents the ip-neigh fallback
    // from running.
    var procSourceAvailable = false
    val procRows = if (expectedInterface.isNullOrBlank()) {
      emptyMap()
    } else {
      try {
        val parsed = parseArpTableForInterface(File("/proc/net/arp").readLines(), expectedInterface)
        procSourceAvailable = true
        parsed
      } catch (error: Exception) {
        Log.w(
          "HomeGuardianScanner",
          "proc arp read failed interface=$expectedInterface error=${error.javaClass.simpleName}",
        )
        emptyMap()
      }
    }
    // Read the kernel's interface-scoped neighbour view as a read-only
    // fallback; both sources still go through the same freshness gate before
    // a MAC enters the payload.
    var ipNeighborSourceAvailable = false
    var ipNeighborFreshStateHosts = emptySet<String>()
    val ipNeighbourRows = try {
      if (expectedInterface.isNullOrBlank()) {
        emptyMap()
      } else {
        // Android app processes do not always inherit a PATH containing
        // /system/bin. Use the absolute binary path so the fallback works on
        // release-like installs as well as on shell-driven tests.
        val process = ProcessBuilder("/system/bin/ip", "neigh", "show", "dev", expectedInterface)
          .redirectErrorStream(true)
          .start()
        val completed = process.waitFor(1, TimeUnit.SECONDS)
        if (!completed) {
          process.destroy()
          emptyMap()
        } else if (process.exitValue() != 0) {
          emptyMap()
        } else {
          val lines = process.inputStream.bufferedReader().use { it.readLines() }
          ipNeighborSourceAvailable = true
          val parsed = parseIpNeighborSnapshotForInterface(lines, expectedInterface)
          ipNeighborFreshStateHosts = parsed.freshStateHosts
          parsed.entries
        }
      }
    } catch (error: Exception) {
      Log.w(
        "HomeGuardianScanner",
        "neighbor table read failed interface=${expectedInterface ?: "none"} error=${error.javaClass.simpleName}",
      )
      emptyMap()
    }
    Log.i(
      "HomeGuardianScanner",
      "neighbor table read interface=${expectedInterface ?: "none"} proc_rows=${procRows.size} ip_rows=${ipNeighbourRows.size}",
    )
    // Prefer the explicit /proc value when both views contain the same host,
    // while retaining valid rows visible only through `ip neigh`.
    return NeighborTableSnapshot(
      entries = ipNeighbourRows + procRows,
      procSourceAvailable = procSourceAvailable,
      ipNeighborSourceAvailable = ipNeighborSourceAvailable,
      freshStateHosts = ipNeighborFreshStateHosts,
    )
  }

  // SSDP LOCATION 의 rootDesc.xml 을 받아 제조사/모델/친근한 이름을 추출한다.
  // ARP 가 막혀 MAC 이 없어도 공유기·스마트TV·프린터 등을 제조사/모델로 식별할 수 있다.
  private fun enrichUpnpDescriptions(
    discoveries: MutableMap<String, MutableDevice>,
    subnetAllowlist: ActiveSubnetAllowlist,
    socketFactory: WifiBoundSocketFactory,
  ) {
    discoveries.values.forEach { device ->
      val location = device.fingerprints
        .firstOrNull { it.startsWith("ssdp-location:") }
        ?.substringAfter("ssdp-location:")
      if (!location.isNullOrBlank()) {
        fetchUpnpDescription(location, device, subnetAllowlist, socketFactory)
      }
    }
  }

  // _spotify-connect 로 발견된 기기마다 ZeroConf getInfo 를 호출해 제조사/모델/종류를 보강한다.
  // resolve 단계가 아니라 여기서 호출해 resolve latch(900ms)를 막지 않는다.
  private fun enrichSpotifyConnect(
    discoveries: MutableMap<String, MutableDevice>,
    socketFactory: WifiBoundSocketFactory,
  ) {
    discoveries.values.forEach { device ->
      val endpoint = device.fingerprints
        .firstOrNull { it.startsWith("spotify-endpoint:") }
        ?.substringAfter("spotify-endpoint:")
      if (!endpoint.isNullOrBlank()) {
        val parts = endpoint.split("|")
        val host = parts.getOrNull(0)?.takeIf { it.isNotBlank() }
        val port = parts.getOrNull(1)?.toIntOrNull()
        val cpath = parts.getOrNull(2)?.takeIf { it.isNotBlank() }
        if (host != null && port != null) {
          fetchSpotifyGetInfo(host, port, cpath, device, socketFactory)
        }
      }
    }
  }

  // Spotify ZeroConf getInfo: 무인증 평문 GET 으로 brandDisplayName/modelDisplayName/deviceType/remoteName 을 받는다.
  // OEM 이 펌웨어에 넣은 값이라 키워드 맵에 없는 브랜드(Sonos/Denon/Samsung 등)도 식별된다(특정 IP/MAC 하드코딩 0).
  // OSS 리시버(librespot 등) 기본값은 하드웨어 제조사가 아니므로 hint 로 채택하지 않고 fingerprint 로만 남긴다(백엔드 OUI 폴백).
  private fun fetchSpotifyGetInfo(
    host: String,
    port: Int,
    cpath: String?,
    device: MutableDevice,
    socketFactory: WifiBoundSocketFactory,
  ) {
    if (device.fingerprints.contains("spotify-getinfo-done")) return
    // 광고된 CPath 가 1순위(기기 자신의 경로라 정확). 다만 CPath 를 못 얻었거나 그 경로가 실패할 수 있어
    // 표준 경로를 항상 뒤에 덧붙여 시도한다. 실제 Family Hub 장치가 17654 포트에서 "/zc/0"
    // 에서 getInfo 가 brandDisplayName="Samsung" 을 반환했다("/"는 404). 한 경로라도 200 이면 즉시 종료.
    val standardPaths = listOf("/", "/zc/0", "/zeroconf")
    val paths =
      if (!cpath.isNullOrBlank()) listOf(cpath) + standardPaths.filter { it != cpath }
      else standardPaths
    for (rawPath in paths) {
      val path = if (rawPath.startsWith("/")) rawPath else "/$rawPath"
      try {
        val separator = if (path.contains("?")) "&" else "?"
        val body = scannerHttpGetBody(
          host,
          port,
          "$path${separator}action=getInfo&version=2.10.0",
          1200,
          socketFactory = socketFactory,
        )
          ?: continue
        val json = org.json.JSONObject(body)
        device.promoteObservationPriority(ObservationPriority.STRUCTURED_DISCOVERY)
        device.fingerprints.add("spotify-getinfo-done")
        val brand = json.optString("brandDisplayName").trim()
        val model = json.optString("modelDisplayName").trim()
        val remote = json.optString("remoteName").trim()
        val type = json.optString("deviceType").trim()
        if (brand.isNotBlank()) device.fingerprints.add("spotify-brand:$brand")
        if (model.isNotBlank()) device.fingerprints.add("spotify-model:$model")
        if (remote.isNotBlank()) device.fingerprints.add("spotify-name:$remote")
        if (type.isNotBlank()) device.fingerprints.add("spotify-type:$type")
        if (brand.isNotBlank() && !isSoftwareReceiverBrand(brand) && device.manufacturerHint == null) {
          device.manufacturerHint = brand
        }
        if (model.isNotBlank() && !isSoftwareReceiverBrand(model) && device.modelHint == null) {
          device.modelHint = model
        }
        if (remote.isNotBlank() && device.nameHint == null) {
          device.nameHint = remote
        }
        applyDiscoveryHints(device, "$brand $model $remote $type")
        return  // 성공 — 나머지 fallback 경로는 시도하지 않는다.
      } catch (_: Exception) {
        // 이 경로 실패 — 다음 fallback 경로 시도(비치명, 스캔 전체 영향 없음).
      }
    }
  }

  /**
   * Scanner-only HTTP over a raw socket. Android's cleartext policy governs
   * HTTP client stacks, but a LAN scan still needs a bounded request to the
   * device that advertised a scanner-discovery endpoint.
   */
  private fun scannerHttpGetBody(
    host: String,
    port: Int,
    path: String,
    timeoutMillis: Int,
    readTimeoutMillis: Int = timeoutMillis * 3,
    socketFactory: WifiBoundSocketFactory,
  ): String? {
    if (
      !path.startsWith("/") || path.length > 512 ||
      path.any { it == '\r' || it == '\n' || it == ' ' }
    ) {
      return null
    }
    return try {
      val boundSocket = socketFactory.openStream() ?: return null
      boundSocket.use { socket ->
        socket.connect(InetSocketAddress(host, port), timeoutMillis)
        socket.soTimeout = readTimeoutMillis
        val request = "GET $path HTTP/1.0\r\nHost: $host\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        socket.getOutputStream().write(request.toByteArray(Charset.forName("UTF-8")))
        socket.getOutputStream().flush()

        val output = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(2048)
        val input = socket.getInputStream()
        while (output.size() < 8192) {
          val remaining = minOf(buffer.size, 8192 - output.size())
          val read = input.read(buffer, 0, remaining)
          if (read <= 0) break
          output.write(buffer, 0, read)
        }
        val response = output.toString("UTF-8")
        val headerEnd = response.indexOf("\r\n\r\n").let { index ->
          if (index >= 0) index + 4 else response.indexOf("\n\n").let { lf -> if (lf >= 0) lf + 2 else -1 }
        }
        if (headerEnd < 0) return null
        val statusLine = response.lineSequence().firstOrNull().orEmpty()
        if (!Regex("HTTP/\\d(?:\\.\\d)?\\s+2\\d\\d").containsMatchIn(statusLine)) return null
        response.substring(headerEnd)
      }
    } catch (_: Exception) {
      null
    }
  }

  private fun enrichKnownProtocolEndpoints(
    discoveries: MutableMap<String, MutableDevice>,
    socketFactory: WifiBoundSocketFactory,
  ) {
    discoveries.values
      .filter { 17654 in it.openPorts && it.fingerprints.none { fp -> fp == "spotify-getinfo-done" } }
      .forEach { device ->
        device.discoverySources.add("spotify-getinfo")
        device.fingerprints.add("spotify-probe:17654")
        fetchSpotifyGetInfo(device.ipAddress, 17654, null, device, socketFactory)
      }
  }

  private fun isSoftwareReceiverBrand(value: String): Boolean {
    return value.trim().lowercase() in setOf(
      "librespot", "go-librespot", "go librespot", "golibrespot",
      "devgianlu", "spotifyd", "raspotify", "spocon", "vollibrespot", "spotify"
    )
  }

  private fun fetchUpnpDescription(
    location: String,
    device: MutableDevice,
    subnetAllowlist: ActiveSubnetAllowlist,
    socketFactory: WifiBoundSocketFactory,
  ) {
    if (device.fingerprints.contains("upnp-desc-fetched")) return
    try {
      val endpoint = java.net.URI(location)
      if (
        !endpoint.scheme.equals("http", ignoreCase = true) ||
        endpoint.rawUserInfo != null ||
        endpoint.rawFragment != null
      ) {
        return
      }
      val host = endpoint.host?.takeIf { it.isNotBlank() } ?: return
      // LOCATION is untrusted device input. Resolve it once through the same
      // active-subnet gate and connect to that allowed IPv4 literal so an
      // SSDP response cannot make the scanner contact another LAN or Internet.
      val allowedHost = subnetAllowlist.resolveAllowedHost(host) ?: return
      // LOCATION may be attacker-controlled even when it resolves somewhere
      // inside the same subnet. Attribute the description only to the actual
      // SSDP response endpoint that created this observation.
      if (!sameIpv4Endpoint(allowedHost, device.ipAddress)) return
      val port = if (endpoint.port == -1) 80 else endpoint.port
      if (port !in 1..65535) return
      val path = buildString {
        append(endpoint.rawPath?.takeIf { it.isNotEmpty() } ?: "/")
        endpoint.rawQuery?.let {
          append('?')
          append(it)
        }
      }
      val xml = scannerHttpGetBody(
        allowedHost,
        port,
        path,
        1_500,
        readTimeoutMillis = 1_500,
        socketFactory = socketFactory,
      ) ?: return
      device.fingerprints.add("upnp-desc-fetched")
      extractBoundedXmlTag(xml, "UDN", maxValueChars = 256)
        ?.let { boundedProtocolIdentityFingerprint("upnp-udn", it) }
        ?.let(device.fingerprints::add)
      extractXmlTag(xml, "manufacturer")?.let {
        device.fingerprints.add("upnp-manufacturer:$it")
        if (device.manufacturerHint == null) device.manufacturerHint = it
      }
      extractXmlTag(xml, "modelName")?.let {
        device.fingerprints.add("upnp-model:$it")
        if (device.modelHint == null) device.modelHint = it
      }
      extractXmlTag(xml, "friendlyName")?.let { if (device.nameHint == null) device.nameHint = it }
      applyDiscoveryHints(device, xml.take(2048))
    } catch (_: Exception) {
      // LOCATION 응답이 없거나 형식이 달라 실패할 수 있다(비치명).
    }
  }

  private fun extractXmlTag(xml: String, tag: String): String? {
    return extractBoundedXmlTag(xml, tag, maxValueChars = 80)
  }

  private fun failedScan(
    started: Long,
    networkContext: Map<String, Any?>,
    code: String,
    scanDiagnostics: Map<String, Any?>? = null,
  ): Map<String, Any?> {
    val failure = safeScanFailure(code)
    return linkedMapOf<String, Any?>(
      "scan_id" to "android-${UUID.randomUUID()}",
      "scan_source" to "android-native",
      "status" to "failed",
      "duration_ms" to (System.currentTimeMillis() - started),
      "network_context" to networkContext,
      "devices_found" to 0,
      "devices" to emptyList<Map<String, Any?>>(),
      "error_code" to failure.code,
      "error_message" to failure.message,
    ).apply {
      if (!scanDiagnostics.isNullOrEmpty()) {
        put("scan_diagnostics", scanDiagnostics)
      }
    }.also {
      Log.w(
        "HomeGuardianScanner",
        "scan failed code=${failure.code} duration_ms=${System.currentTimeMillis() - started}",
      )
    }
  }

  private fun numberOption(value: Any?, fallback: Int): Int {
    return when (value) {
      is Number -> value.toInt()
      is String -> value.toIntOrNull() ?: fallback
      else -> fallback
    }
  }

  private fun portsOption(value: Any?): List<Int> {
    return (value as? List<*>)?.mapNotNull {
      when (it) {
        is Number -> it.toInt()
        is String -> it.toIntOrNull()
        else -> null
      }
    }?.filter { it in 1..65535 }?.distinct() ?: emptyList()
  }

  private fun parseHeaders(response: String): Map<String, String> {
    return response.lines()
      .mapNotNull { line ->
        val index = line.indexOf(":")
        if (index <= 0) null else line.substring(0, index).trim().lowercase() to line.substring(index + 1).trim()
      }
      .toMap()
  }

  private fun applyDiscoveryHints(device: MutableDevice, text: String) {
    val lower = text.lowercase()
    // 구분자(공백/하이픈)를 없앤 사본 — getInfo modelDisplayName 은 "Family Hub"(공백), mDNS 이름은
    // "Samsung-FamilyHub"(하이픈)처럼 표기가 갈린다. 백엔드와 동일하게 변형에 무관하게 매칭한다.
    val compact = lower.replace("-", "").replace(" ", "")
    // 카메라/영상
    if ("onvif" in lower || "networkvideotransmitter" in lower || "camera" in lower || "ipcam" in lower || "axis-video" in lower || "rtsp" in lower) {
      device.deviceTypeHint = "camera"
      device.fingerprints.add("camera-discovery-hint")
    }
    // 공유기/게이트웨이
    if ("router" in lower || "gateway" in lower || "tplink" in lower || "tp-link" in lower || "asus" in lower || "netgear" in lower || "iptime" in lower || "dlink" in lower || "d-link" in lower) {
      if (device.deviceTypeHint == null) device.deviceTypeHint = "router"
    }
    // 스마트홈 - 삼성 패밀리허브/스마트싱스, LG ThinQ
    if ("familyhub" in compact || ("samsung" in lower && ("fridge" in lower || "refrigerator" in lower || "냉장고" in lower))) {
      device.deviceTypeHint = "fridge"
      device.manufacturerHint = "Samsung"
      device.fingerprints.add("samsung-family-hub")
    }
    if ("thinq" in lower || "lg-smart-device" in lower || ("lge" in lower && ("fridge" in lower || "tv" in lower || "washer" in lower))) {
      device.manufacturerHint = "LG"
    }
    // ThinQ advertises several appliance families through the same service.
    // Promote only explicit product evidence; the service name alone is not
    // enough to call a soundbar, TV, washer, or other appliance an AC.
    if ("air conditioner" in lower || "air-conditioner" in lower || "aircon" in lower ||
      "lg_ac" in lower || "lge_ac" in lower || "air_conditioner" in lower) {
      device.deviceTypeHint = "air_conditioner"
      device.manufacturerHint = "LG"
      device.fingerprints.add("lg-air-conditioner-evidence")
    }
    // TV / 미디어
    if ("googlecast" in lower || "chromecast" in lower) {
      device.deviceTypeHint = "tv"
      device.manufacturerHint = device.manufacturerHint ?: "Google"
    }
    if ("airplay" in lower || "appletv" in lower || "apple-tv" in lower) {
      device.deviceTypeHint = "tv"
      device.manufacturerHint = device.manufacturerHint ?: "Apple"
    }
    if ("samsungmsf" in lower || "samsungtv" in lower) {
      device.deviceTypeHint = "tv"
      device.manufacturerHint = "Samsung"
    }
    if ("androidtv" in lower || "android-tv" in lower) {
      device.deviceTypeHint = "tv"
    }
    // 오디오(스피커/사운드바/리시버 등) — "스피커" 로 단정하지 않고 "audio" 로 둔다.
    // Spotify Connect/AirPlay 는 TV·사운드바·PC 도 광고하므로 스피커 단정은 오탐. 백엔드가 신호로 세분.
    if ("spotify-connect" in lower || "raop" in lower || "airtunes" in lower || "sonos" in lower) {
      if (device.deviceTypeHint == null) device.deviceTypeHint = "audio"
    }
    // 도어록 / 플러그 / 허브
    if ("doorlock" in lower || "smartlock" in lower || "samsung-shp" in lower || "도어락" in lower) {
      device.deviceTypeHint = "lock"
    }
    if ("smartplug" in lower || "smart-plug" in lower || "plug" in lower || "switch_" in lower || "hs100" in lower || "hs110" in lower) {
      if (device.deviceTypeHint == null) device.deviceTypeHint = "plug"
    }
    if ("smartthings" in lower || "matter" in lower || "homekit" in lower || "hue" in lower || "bridge" in lower || "hub" in lower) {
      if (device.deviceTypeHint == null) device.deviceTypeHint = "hub"
    }
    // 모바일/노트북/프린터
    if ("iphone" in lower || "ipad" in lower || "android-phone" in lower || "galaxy" in lower) {
      if (device.deviceTypeHint == null) device.deviceTypeHint = "phone"
    }
    if ("ipp" in lower || "printer" in lower || "officejet" in lower || "laserjet" in lower) {
      if (device.deviceTypeHint == null) device.deviceTypeHint = "printer"
    }

    // A friendlyName/hostname may be a resident label.  A Server header is
    // deliberately excluded because it is only firmware evidence.
    val nameMatch = Regex("(friendlyname|hostname)[:= ]+([^\\r\\n<]{3,80})", RegexOption.IGNORE_CASE).find(text)
    if (nameMatch != null && device.nameHint == null) {
      device.nameHint = nameMatch.groupValues.last().trim()
    }
    val modelMatch = Regex("(model(name)?)[:= ]+([^\\r\\n<]{3,80})", RegexOption.IGNORE_CASE).find(text)
    if (modelMatch != null && device.modelHint == null) {
      device.modelHint = modelMatch.groupValues.last().trim()
    }
    // mDNS serviceName 또는 SSDP server header 자체에 의미 있는 이름이 들어있는 경우.
    val mdnsName = Regex("mdns-name:([^\\s\\r\\n]+)", RegexOption.IGNORE_CASE).find(text)
    if (mdnsName != null && device.nameHint == null) {
      device.nameHint = mdnsName.groupValues[1].trim()
    }
  }

  private fun buildSelfDevicePayload(
    localIp: String,
    context: Map<String, Any?>,
    arpTable: Map<String, String>
  ): Map<String, Any?> {
    val manufacturer = Build.MANUFACTURER?.takeIf { it.isNotBlank() } ?: ""
    val model = Build.MODEL?.takeIf { it.isNotBlank() } ?: "휴대폰"
    val deviceType = classifySelfAndroidDeviceType(model)
    val deviceTypeLabel = if (deviceType == "tablet") "태블릿" else "휴대폰"
    val mac = arpTable[localIp] ?: "본인-기기"
    val deviceId = if (arpTable[localIp] != null) "device-${arpTable[localIp]!!.replace(":", "-")}" else "self-${localIp.replace(".", "-")}"
    return mapOf(
      "device_id" to deviceId,
      "name" to "내 $deviceTypeLabel ($model)",
      "device_type" to deviceType,
      "manufacturer" to manufacturer,
      "model" to model,
      "ip_address" to localIp,
      "mac_address" to mac,
      "online" to true,
      "last_seen" to currentUtcTimestamp(),
      "open_ports" to emptyList<Int>(),
      "services" to listOf("self-device"),
      "default_credentials" to false,
      "encryption" to "unknown",
      "vulnerabilities" to emptyList<Map<String, Any?>>(),
      "discovery_sources" to listOf("self"),
      "fingerprints" to listOf(
        "self-android",
        "self-manufacturer:$manufacturer",
        "self-model:$model"
      ),
      "risk_signals" to listOf("self_device"),
      "confidence" to 1.0
    )
  }

  private fun riskRank(device: MutableDevice): Int {
    return when {
      23 in device.openPorts || 554 in device.openPorts -> 0
      1900 in device.openPorts || 3702 in device.openPorts -> 1
      else -> 2
    }
  }
}

private val SAMSUNG_TABLET_MODEL_PATTERN = Regex("^SM-[PTX][0-9][A-Z0-9-]*$")

internal fun classifySelfAndroidDeviceType(model: String?): String {
  val normalizedModel = model?.trim()?.uppercase(Locale.ROOT).orEmpty()
  return if (SAMSUNG_TABLET_MODEL_PATTERN.matches(normalizedModel)) "tablet" else "phone"
}

private fun boundedEvidenceFingerprint(
  prefix: String,
  rawValue: String?,
  maxValueChars: Int = 256,
): String? {
  val value = rawValue?.trim()?.takeIf(String::isNotBlank) ?: return null
  if (value.length > maxValueChars || value.any { it.code < 0x20 || it.code == 0x7F }) return null
  return "$prefix:$value"
}

internal fun boundedProtocolIdentityFingerprint(
  prefix: String,
  rawValue: String?,
  maxValueChars: Int = 256,
): String? {
  if (prefix != "ssdp-usn" && prefix != "upnp-udn") return null
  val bounded = boundedEvidenceFingerprint(prefix, rawValue, maxValueChars)
    ?.substringAfter(':')
    ?: return null
  val root = bounded.substringBefore("::").trim()
  if (!root.startsWith("uuid:", ignoreCase = true)) return null
  val uuidText = root.substringAfter(':').trim()
  if (!uuidText.matches(Regex("[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}"))) return null
  val uuid = runCatching { UUID.fromString(uuidText) }.getOrNull()
    ?.takeIf { it.mostSignificantBits != 0L || it.leastSignificantBits != 0L }
    ?: return null
  val suffix = bounded.substringAfter("::", missingDelimiterValue = "").trim()
  if (prefix == "upnp-udn" && suffix.isNotEmpty()) return null
  val canonicalRoot = "uuid:${uuid.toString().lowercase(Locale.ROOT)}"
  return if (suffix.isEmpty()) "$prefix:$canonicalRoot" else "$prefix:$canonicalRoot::$suffix"
}

internal fun sameIpv4Endpoint(first: String?, second: String?): Boolean {
  val firstValue = first?.let(::parseStandardIpv4) ?: return false
  val secondValue = second?.let(::parseStandardIpv4) ?: return false
  return firstValue == secondValue
}

internal fun extractBoundedXmlTag(
  xml: String,
  tag: String,
  maxValueChars: Int,
): String? {
  if (tag.isBlank() || maxValueChars !in 1..512) return null
  val escapedTag = Regex.escape(tag)
  val qualifiedTag = "(?:[A-Za-z_][A-Za-z0-9_.-]*:)?$escapedTag"
  val matched = Regex(
    "<$qualifiedTag(?:\\s[^>]*)?>([^<]{1,${maxValueChars + 1}})</$qualifiedTag\\s*>",
    RegexOption.IGNORE_CASE,
  ).find(xml) ?: return null
  val value = matched.groupValues[1].trim()
  return value
    .takeIf(String::isNotBlank)
    ?.takeIf { it.length <= maxValueChars && it.none { char -> char.code < 0x20 || char.code == 0x7F } }
}

internal data class MdnsHostAttribution(
  val ipAddress: String,
  val ports: Set<Int>,
  val fingerprints: Set<String>,
)

private const val DNS_SD_META_QUERY_NAME = "_services._dns-sd._udp.local"
private val DNS_SD_SERVICE_LABEL = Regex("^_[A-Za-z0-9](?:[A-Za-z0-9-]{0,60}[A-Za-z0-9])?$")

/**
 * Normalize only a DNS-SD base service type under the link-local mDNS domain.
 * Subtypes, arbitrary host names, Unicode lookalikes, and non-local domains
 * are rejected before any follow-up packet can be sent.
 */
internal fun normalizeLocalDnsSdServiceType(candidate: String): String? {
  val labels = candidate.trim().trimEnd('.').split('.')
  if (labels.size != 3) return null
  val service = labels[0]
  val transport = labels[1]
  val domain = labels[2]
  if (!DNS_SD_SERVICE_LABEL.matches(service)) return null
  if (!transport.equals("_tcp", ignoreCase = true) && !transport.equals("_udp", ignoreCase = true)) {
    return null
  }
  if (!domain.equals("local", ignoreCase = true)) return null
  return "${service.lowercase(Locale.ROOT)}.${transport.lowercase(Locale.ROOT)}.local"
}

/**
 * Extract service types only from PTR records owned by the standard DNS-SD
 * meta-query name. The parser is deliberately independent from device
 * attribution: a discovered type is merely a bounded query target and never
 * product identity evidence by itself.
 */
internal fun parseDnsSdServiceTypes(
  data: ByteArray,
  maxTypes: Int,
): List<String> {
  val limit = maxTypes.coerceIn(0, 64)
  if (limit == 0 || data.size < 12) return emptyList()

  fun unsignedShort(offset: Int): Int? {
    if (offset < 0 || offset + 1 >= data.size) return null
    return ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
  }

  fun readName(start: Int): Pair<String, Int>? {
    if (start !in data.indices) return null
    val labels = mutableListOf<String>()
    val visitedOffsets = mutableSetOf<Int>()
    var offset = start
    var nextOffset: Int? = null
    var labelsRead = 0
    while (labelsRead++ < 128) {
      if (offset !in data.indices || !visitedOffsets.add(offset)) return null
      val length = data[offset].toInt() and 0xFF
      when {
        length == 0 -> return labels.joinToString(".") to (nextOffset ?: (offset + 1))
        length and 0xC0 == 0xC0 -> {
          if (offset + 1 >= data.size) return null
          val pointer = ((length and 0x3F) shl 8) or (data[offset + 1].toInt() and 0xFF)
          if (pointer !in data.indices) return null
          if (nextOffset == null) nextOffset = offset + 2
          offset = pointer
        }
        length and 0xC0 != 0 || length > 63 || offset + 1 + length > data.size -> return null
        else -> {
          labels.add(String(data, offset + 1, length, Charset.forName("US-ASCII")))
          offset += 1 + length
        }
      }
    }
    return null
  }

  val questionCount = unsignedShort(4) ?: return emptyList()
  val recordCount = listOf(6, 8, 10).sumOf { unsignedShort(it) ?: return emptyList() }
  // A raw packet is capped at 9 KB by the caller. Refuse absurd header counts
  // instead of spending time walking attacker-controlled empty records.
  if (questionCount > 128 || recordCount > 512) return emptyList()
  var offset = 12
  repeat(questionCount) {
    val question = readName(offset) ?: return emptyList()
    offset = question.second
    if (offset + 4 > data.size) return emptyList()
    offset += 4
  }

  val result = linkedSetOf<String>()
  repeat(recordCount) {
    val owner = readName(offset) ?: return emptyList()
    offset = owner.second
    val recordType = unsignedShort(offset) ?: return emptyList()
    val dataLength = unsignedShort(offset + 8) ?: return emptyList()
    val dataStart = offset + 10
    val dataEnd = dataStart + dataLength
    if (dataStart < offset || dataEnd < dataStart || dataEnd > data.size) return emptyList()
    if (
      recordType == 12 &&
      owner.first.trim().trimEnd('.').equals(DNS_SD_META_QUERY_NAME, ignoreCase = true)
    ) {
      val target = readName(dataStart)
      if (target != null && target.second <= dataEnd) {
        normalizeLocalDnsSdServiceType(target.first)?.let(result::add)
      }
    }
    offset = dataEnd
  }
  return result.take(limit)
}

private data class MdnsSrvBinding(
  val targetName: String,
  val port: Int,
)

private data class MutableMdnsServiceBinding(
  var displayName: String,
  val serviceTypes: MutableSet<String> = linkedSetOf(),
  val srvBindings: MutableList<MdnsSrvBinding> = mutableListOf(),
  val txtValues: MutableSet<String> = linkedSetOf(),
)

private data class MutableMdnsHostAttribution(
  val ports: MutableSet<Int> = sortedSetOf(),
  val fingerprints: MutableSet<String> = linkedSetOf(),
)

/**
 * Attributes raw DNS-SD evidence to the host advertised by each service.
 *
 * An mDNS datagram can contain records for several responders. The UDP source
 * address therefore cannot be used as a bucket for every PTR/SRV/TXT record.
 * Evidence follows PTR instance -> SRV target -> A/AAAA address instead. The
 * source address is used only when every usable SRV record names one target
 * and the packet omits address records entirely, which is the bounded fallback
 * for a single responder that relies on the datagram source as its address.
 */
internal fun parseMdnsAttributions(
  data: ByteArray,
  sourceIp: String,
): List<MdnsHostAttribution> {
  if (data.size < 12) return emptyList()

  fun unsignedShort(offset: Int): Int? {
    if (offset < 0 || offset + 1 >= data.size) return null
    return ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
  }

  fun readName(start: Int): Pair<String, Int>? {
    if (start !in data.indices) return null
    val labels = mutableListOf<String>()
    val visitedOffsets = mutableSetOf<Int>()
    var offset = start
    var nextOffset: Int? = null
    var labelsRead = 0

    while (labelsRead++ < 128) {
      if (offset !in data.indices || !visitedOffsets.add(offset)) return null
      val length = data[offset].toInt() and 0xFF
      when {
        length == 0 -> {
          val next = nextOffset ?: (offset + 1)
          return labels.joinToString(".") to next
        }

        length and 0xC0 == 0xC0 -> {
          if (offset + 1 >= data.size) return null
          val pointer = ((length and 0x3F) shl 8) or (data[offset + 1].toInt() and 0xFF)
          if (pointer !in data.indices) return null
          if (nextOffset == null) nextOffset = offset + 2
          offset = pointer
        }

        length and 0xC0 != 0 || length > 63 || offset + 1 + length > data.size -> return null

        else -> {
          labels.add(String(data, offset + 1, length, Charset.forName("UTF-8")))
          offset += 1 + length
        }
      }
    }
    return null
  }

  fun normalizedName(value: String): String = value.trim().trimEnd('.').lowercase(Locale.ROOT)

  fun inferredServiceType(instanceName: String): String? {
    val labels = instanceName.trimEnd('.').split('.')
    val serviceIndex = labels.indices.firstOrNull { index ->
      labels[index].startsWith("_") &&
        index + 1 < labels.size &&
        (labels[index + 1].equals("_tcp", ignoreCase = true) ||
          labels[index + 1].equals("_udp", ignoreCase = true))
    } ?: return null
    return labels.drop(serviceIndex).joinToString(".")
  }

  val questionCount = unsignedShort(4) ?: return emptyList()
  val answerCount = unsignedShort(6) ?: return emptyList()
  val authorityCount = unsignedShort(8) ?: return emptyList()
  val additionalCount = unsignedShort(10) ?: return emptyList()
  val recordCount = answerCount + authorityCount + additionalCount
  if (questionCount > 128 || recordCount > NATIVE_SCAN_HOST_HARD_CAP) return emptyList()
  var offset = 12

  repeat(questionCount) {
    val questionName = readName(offset) ?: return emptyList()
    offset = questionName.second
    if (offset + 4 > data.size) return emptyList()
    offset += 4
  }

  val ptrRecords = mutableListOf<Pair<String, String>>()
  val srvRecords = linkedMapOf<String, MutableList<MdnsSrvBinding>>()
  val srvDisplayNames = linkedMapOf<String, String>()
  val txtRecords = linkedMapOf<String, MutableSet<String>>()
  val addressesByHost = linkedMapOf<String, MutableSet<String>>()
  var addressRecordCount = 0

  repeat(recordCount) {
    val owner = readName(offset) ?: return emptyList()
    val ownerName = owner.first.trimEnd('.')
    val ownerKey = normalizedName(ownerName)
    offset = owner.second
    val recordType = unsignedShort(offset) ?: return emptyList()
    val dataLength = unsignedShort(offset + 8) ?: return emptyList()
    val dataStart = offset + 10
    val dataEnd = dataStart + dataLength
    if (dataEnd > data.size) return emptyList()

    when (recordType) {
      1 -> { // A
        addressRecordCount += 1
        if (dataLength == 4 && ownerKey.isNotBlank()) {
          val address = runCatching {
            InetAddress.getByAddress(data.copyOfRange(dataStart, dataEnd)).hostAddress
          }.getOrNull()
          if (!address.isNullOrBlank()) addressesByHost.getOrPut(ownerKey) { linkedSetOf() }.add(address)
        }
      }

      12 -> { // PTR: owner=service type, rdata=service instance
        val target = readName(dataStart)
        if (target != null && target.second <= dataEnd && ownerName.isNotBlank() && target.first.isNotBlank()) {
          ptrRecords.add(ownerName to target.first.trimEnd('.'))
        }
      }

      16 -> { // TXT: owner=service instance
        var textOffset = dataStart
        val texts = txtRecords.getOrPut(ownerKey) { linkedSetOf() }
        while (textOffset < dataEnd) {
          val length = data[textOffset].toInt() and 0xFF
          textOffset += 1
          if (textOffset + length > dataEnd) break
          val text = String(data, textOffset, length, Charset.forName("UTF-8"))
          if (text.isNotBlank()) texts.add(text)
          textOffset += length
        }
      }

      28 -> { // AAAA
        addressRecordCount += 1
        if (dataLength == 16 && ownerKey.isNotBlank()) {
          val address = runCatching {
            InetAddress.getByAddress(data.copyOfRange(dataStart, dataEnd)).hostAddress
          }.getOrNull()
          if (!address.isNullOrBlank()) addressesByHost.getOrPut(ownerKey) { linkedSetOf() }.add(address)
        }
      }

      33 -> { // SRV: owner=service instance, rdata=priority, weight, port, target
        if (dataLength >= 7 && ownerKey.isNotBlank()) {
          val port = unsignedShort(dataStart + 4) ?: 0
          val target = readName(dataStart + 6)
          if (target != null && target.second <= dataEnd && target.first.isNotBlank()) {
            srvDisplayNames.putIfAbsent(ownerKey, ownerName)
            srvRecords.getOrPut(ownerKey) { mutableListOf() }.add(
              MdnsSrvBinding(targetName = target.first.trimEnd('.'), port = port),
            )
          }
        }
      }
    }
    offset = dataEnd
  }

  val serviceBindings = linkedMapOf<String, MutableMdnsServiceBinding>()
  ptrRecords.forEach { (serviceType, instanceName) ->
    val instanceKey = normalizedName(instanceName)
    if (instanceKey.isBlank()) return@forEach
    val binding = serviceBindings.getOrPut(instanceKey) { MutableMdnsServiceBinding(instanceName) }
    binding.serviceTypes.add(serviceType)
  }
  srvRecords.forEach { (instanceKey, records) ->
    val displayName = srvDisplayNames[instanceKey].orEmpty()
    val binding = serviceBindings.getOrPut(instanceKey) { MutableMdnsServiceBinding(displayName) }
    if (binding.displayName.isBlank()) binding.displayName = displayName
    binding.srvBindings.addAll(records)
    inferredServiceType(binding.displayName)?.let(binding.serviceTypes::add)
    binding.txtValues.addAll(txtRecords[instanceKey].orEmpty())
  }

  val distinctSrvTargets = serviceBindings.values
    .flatMap { binding -> binding.srvBindings.map { normalizedName(it.targetName) } }
    .filter(String::isNotBlank)
    .toSet()
  val sourceFallbackTarget = distinctSrvTargets.singleOrNull()
    ?.takeIf { addressRecordCount == 0 && sourceIp.isNotBlank() }

  val byAddress = linkedMapOf<String, MutableMdnsHostAttribution>()
  serviceBindings.values.forEach { binding ->
    if (binding.srvBindings.isEmpty() || binding.serviceTypes.isEmpty()) return@forEach
    binding.srvBindings.forEach { srv ->
      val targetKey = normalizedName(srv.targetName)
      val addresses = addressesByHost[targetKey].orEmpty().ifEmpty {
        if (targetKey == sourceFallbackTarget) setOf(sourceIp) else emptySet()
      }
      addresses.forEach { address ->
        val attribution = byAddress.getOrPut(address) { MutableMdnsHostAttribution() }
        if (srv.port in 1..65535) attribution.ports.add(srv.port)
        binding.serviceTypes.forEach { attribution.fingerprints.add("mdns-type:$it") }
        if (binding.displayName.isNotBlank()) {
          attribution.fingerprints.add("mdns-name:${binding.displayName}")
        }
        binding.txtValues.forEach { attribution.fingerprints.add("mdns-txt:$it") }
      }
    }
  }

  return byAddress.map { (address, attribution) ->
    MdnsHostAttribution(
      ipAddress = address,
      ports = attribution.ports.toSet(),
      fingerprints = attribution.fingerprints.toSet(),
    )
  }
}

internal data class MutableDevice(
  val ipAddress: String,
  val openPorts: MutableSet<Int> = sortedSetOf(),
  val services: MutableSet<String> = sortedSetOf(),
  val discoverySources: MutableSet<String> = sortedSetOf(),
  val fingerprints: MutableSet<String> = BoundedLinkedHashSet(MAX_FINGERPRINTS_PER_DEVICE),
  var deviceTypeHint: String? = null,
  var modelHint: String? = null,
  var nameHint: String? = null,
  var manufacturerHint: String? = null,
  var firmwareHint: String? = null
) {
  internal var observationPriority: ObservationPriority = ObservationPriority.TCP_ONLY
    private set

  internal fun promoteObservationPriority(priority: ObservationPriority) {
    if (priority.rank > observationPriority.rank) observationPriority = priority
  }

  fun toPayload(arpMac: String?): Map<String, Any?> {
    val ports = openPorts.toList().sorted()
    // An open transport is presence/risk evidence only. Product/type evidence
    // must come from a structured protocol response or backend enrichment.
    val type = deviceTypeHint ?: "unknown"
    val riskSignals = riskSignals(type, ports, discoverySources)
    // An advertised service name/TXT/body is spoofable evidence, not physical
    // identity. Only the current-interface ARP map that passed this scan's
    // freshness gate may produce mac_address or a MAC-derived device_id.
    val verifiedMac = arpMac
      ?.uppercase()
      ?.takeIf { it.matches(Regex("([0-9A-F]{2}:){5}[0-9A-F]{2}")) }
    // OUI 제조사 식별은 백엔드의 IEEE 전체 DB(약 3.9만 vendor)에 위임한다. native 는 MAC 만 정확히 전달.
    // Native scanning only transports evidence.  Product identity, model
    // confidence and the resident-facing name are decided by the backend.
    val finalManufacturer = manufacturerHint ?: ""
    val finalName = nameHint?.let { cleanFriendlyName(it, type) } ?: ""
    return linkedMapOf<String, Any?>(
      "device_id" to if (verifiedMac != null) "device-${verifiedMac.replace(":", "-")}" else "local-${ipAddress.replace(".", "-")}",
      "name" to finalName,
      "device_type" to type,
      "manufacturer" to finalManufacturer,
      "model" to (modelHint ?: ""),
      "firmware" to (firmwareHint ?: ""),
      "ip_address" to ipAddress,
      "online" to true,
      "last_seen" to currentUtcTimestamp(),
      "open_ports" to ports,
      "services" to services.toList().sorted(),
      "default_credentials" to false,
      "encryption" to "unknown",
      "vulnerabilities" to emptyList<Map<String, Any?>>(),
      "discovery_sources" to discoverySources.toList().sorted(),
      "fingerprints" to fingerprints.toList().sorted(),
      "risk_signals" to riskSignals,
      "identity_status" to "enriching",
      "confidence" to confidenceScore(),
    ).apply {
      if (verifiedMac != null) put("mac_address", verifiedMac)
    }
  }

  private fun confidenceScore(): Double {
    var score = 0.35
    if (discoverySources.isNotEmpty()) score += 0.2
    if (openPorts.isNotEmpty()) score += 0.2
    if (fingerprints.isNotEmpty()) score += 0.15
    if (modelHint != null || nameHint != null) score += 0.1
    return min(score, 0.95)
  }
}

private fun guessDeviceName(ipAddress: String, deviceType: String): String {
  // Compatibility shim: never turn a port/category hint or an IP address
  // into a user-facing product name.
  return ""
}

// mDNS friendlyName/SSDP server header 에서 추출한 이름을 사용자에게 보여주기 좋게 정리.
// 예: "Samsung Family Hub._http._tcp.local." → "Samsung Family Hub"
private fun cleanFriendlyName(rawName: String, deviceType: String): String {
  val truncated = rawName
    .substringBefore("._tcp.")
    .substringBefore("._udp.")
    .substringBefore(".local.")
    .substringBefore(".local")
    .replace("\\", " ")
    .replace("/", " ")
    .replace(":", " ")
    .trim()
  if (truncated.length < 3) return rawName.take(60)
  val typeLabel = when (deviceType) {
    "fridge" -> "냉장고"
    "tv" -> "TV"
    "camera" -> "카메라"
    "router" -> "공유기"
    "speaker" -> "스피커"
    "lock" -> "도어록"
    "plug" -> "스마트 플러그"
    "hub" -> "스마트 허브"
    "phone" -> "휴대폰"
    "printer" -> "프린터"
    else -> null
  }
  return if (typeLabel != null) "$truncated ($typeLabel)" else truncated
}

private fun riskSignals(deviceType: String, ports: List<Int>, sources: Set<String>): List<String> {
  val signals = mutableListOf<String>()
  if (deviceType == "camera" || 554 in ports || 3702 in ports || "onvif" in sources || "ws-discovery" in sources) {
    signals.add("camera_candidate")
  }
  if (23 in ports) signals.add("telnet_open")
  if (554 in ports) signals.add("rtsp_open")
  if (1900 in ports || "ssdp" in sources) signals.add("upnp_exposed")
  if (3702 in ports || "ws-discovery" in sources) signals.add("onvif_discovery")
  if (80 in ports || 8080 in ports) signals.add("http_admin_candidate")
  if (ports.size >= 5) signals.add("wide_attack_surface")
  if ((23 in ports || 80 in ports || 8080 in ports) && deviceType in setOf("camera", "iot", "web-device")) {
    signals.add("default_credentials_possible")
  }
  return signals.distinct()
}

private fun mdnsServiceName(serviceType: String?): String {
  return when (serviceType) {
    "_http._tcp." -> "mdns-http"
    "_https._tcp." -> "mdns-https"
    "_rtsp._tcp." -> "mdns-rtsp"
    "_onvif._tcp." -> "mdns-onvif"
    "_axis-video._tcp." -> "mdns-axis-video"
    "_hap._tcp." -> "mdns-homekit"
    else -> "mdns"
  }
}

private fun intToIp(value: Int): String? {
  if (value == 0) return null
  return listOf(
    value and 0xff,
    value shr 8 and 0xff,
    value shr 16 and 0xff,
    value shr 24 and 0xff
  ).joinToString(".")
}

/**
 * Select the IPv4 address/prefix captured from the active Wi-Fi Network's
 * LinkProperties. WifiInfo's reported address is only a disambiguation hint
 * when an interface has multiple IPv4 addresses; it never supplies the mask.
 */
internal fun selectLinkPropertiesWifiSubnet(
  linkAddresses: List<CapturedIpv4LinkAddress>,
  reportedWifiIp: String?,
): AuthoritativeWifiSubnet? {
  val candidates = linkAddresses.filter(::isUsableLinkPropertiesWifiAddress).mapNotNull { captured ->
    val normalizedIp = captured.address.trim()
    val cidr = subnetCidrFromPrefix(normalizedIp, captured.prefixLength) ?: return@mapNotNull null
    AuthoritativeWifiSubnet(
      localIp = normalizedIp,
      subnetCidr = cidr,
      source = "link-properties",
    )
  }.distinctBy { "${it.localIp}|${it.subnetCidr}" }

  val reportedMatch = reportedWifiIp?.let { reported ->
    candidates.singleOrNull { it.localIp == reported }
  }
  return reportedMatch ?: candidates.singleOrNull()
}

internal fun hasUsableLinkPropertiesWifiAddress(
  linkAddresses: List<CapturedIpv4LinkAddress>,
): Boolean = linkAddresses.any(::isUsableLinkPropertiesWifiAddress)

private fun isUsableLinkPropertiesWifiAddress(captured: CapturedIpv4LinkAddress): Boolean {
  val normalizedIp = captured.address.trim()
  return parseStandardIpv4(normalizedIp) != null &&
    isPrivateIpv4(normalizedIp) &&
    captured.prefixLength in 1..30
}

/**
 * Last-resort DHCP fallback for vendor builds that expose no IPv4 LinkAddress.
 * DhcpInfo.netmask has appeared in both byte orders. Try both, but accept only
 * a contiguous standard mask whose subnet contains both the local IP and the
 * gateway. Ambiguous or inconsistent inputs fail closed.
 */
internal fun validatedDhcpWifiSubnet(
  localIp: String?,
  gatewayIp: String?,
  rawNetmask: Int,
): AuthoritativeWifiSubnet? {
  val local = localIp?.takeIf(::isPrivateIpv4) ?: return null
  val gateway = gatewayIp?.takeIf(::isPrivateIpv4) ?: return null
  val rawMask = rawNetmask.toLong() and 0xffffffffL
  val reversedMask = Integer.reverseBytes(rawNetmask).toLong() and 0xffffffffL
  val candidates = listOf(rawMask, reversedMask)
    .distinct()
    .mapNotNull { mask ->
      val prefix = prefixLengthFromStandardMask(mask) ?: return@mapNotNull null
      val cidr = subnetCidrFromPrefix(local, prefix) ?: return@mapNotNull null
      if (!ipv4HostBelongsToCidr(local, cidr) || !ipv4HostBelongsToCidr(gateway, cidr)) {
        return@mapNotNull null
      }
      AuthoritativeWifiSubnet(
        localIp = local,
        subnetCidr = cidr,
        source = "validated-dhcp-fallback",
        gatewayIp = gateway,
      )
    }
    .distinctBy { it.subnetCidr }
  return candidates.singleOrNull()
}

private fun prefixLengthFromStandardMask(mask: Long): Int? {
  val normalized = mask and 0xffffffffL
  val inverted = normalized xor 0xffffffffL
  // A valid high-bit mask has an inverted value of 2^n - 1.
  if (inverted and (inverted + 1L) != 0L) return null
  return java.lang.Long.bitCount(normalized).takeIf { it in 1..30 }
}

private fun subnetCidrFromPrefix(ipAddress: String, prefixLength: Int): String? {
  val ip = parseStandardIpv4(ipAddress) ?: return null
  if (prefixLength !in 1..30) return null
  val mask = (0xffffffffL shl (32 - prefixLength)) and 0xffffffffL
  val network = ip and mask
  return "${intToStandardIpv4(network)}/$prefixLength"
}

private fun ipv4HostBelongsToCidr(ipAddress: String, cidr: String): Boolean {
  val value = parseStandardIpv4(ipAddress) ?: return false
  val range = ipv4RangeFromCidr(cidr) ?: return false
  return value in range.first..range.last
}

/**
 * Build the actual local-subnet host list instead of assuming every Wi-Fi is
 * a /24. Interface-scoped ARP entries reserve slots inside (never beyond) the
 * hard cap; this recovers devices Android already knows about on /16-/20
 * networks without scanning an unbounded private network.
 */
internal fun buildCandidateHosts(
  localIp: String,
  subnetCidr: String?,
  arpIps: Collection<String>,
  maxHosts: Int,
  gatewayIp: String? = null,
): List<String> {
  // The caller supplies the captured LinkProperties CIDR (or the separately
  // validated DHCP fallback). Never reinterpret a raw DHCP netmask here.
  val range = ipv4RangeFromCidr(subnetCidr) ?: return emptyList()
  val first = range.first
  val last = range.last
  val localValue = parseStandardIpv4(localIp) ?: return emptyList()
  if (first > last) return emptyList()
  val hostCount = last - first + 1L
  val localOffset = (localValue - first).takeIf { localValue in first..last }
  val remoteHostCount = hostCount - if (localOffset == null) 0L else 1L
  val limit = min(
    remoteHostCount,
    maxHosts.toLong().coerceIn(1L, NATIVE_SCAN_HOST_HARD_CAP.toLong()),
  ).toInt()
  val hosts = LinkedHashSet<String>()

  // A valid gateway and interface-scoped neighbour rows are the highest-value
  // unicast candidates. Reserve their slots before numeric sampling, while
  // still applying the same subnet and strict host-count boundary.
  parseStandardIpv4(gatewayIp.orEmpty())
    ?.takeIf { it in first..last && it != localValue }
    ?.let(::intToStandardIpv4)
    ?.let(hosts::add)
  arpIps.asSequence()
    .mapNotNull(::parseStandardIpv4)
    .filter { it in first..last && it != localValue }
    .mapNotNull(::intToStandardIpv4)
    .distinct()
    .take((limit - hosts.size).coerceAtLeast(0))
    .forEach(hosts::add)

  // Large enterprise/home-mesh CIDRs are usually routed internally in /24
  // neighbourhoods. Scan the handset's /24 and, when different, the
  // gateway's /24 in round-robin order before spending the bounded budget on
  // sparse whole-CIDR samples. This keeps nearby IoT/PC hosts from vanishing
  // merely because their numeric address falls between proportional samples.
  val priorityBlocks = linkedSetOf<Long>()
  parseStandardIpv4(gatewayIp.orEmpty())
    ?.takeIf { it in first..last }
    ?.let { priorityBlocks.add(it and 0xffffff00L) }
  priorityBlocks.add(localValue and 0xffffff00L)
  val priorityRanges = priorityBlocks.mapNotNull { block ->
    val blockFirst = maxOf(first, block + 1L)
    val blockLast = minOf(last, block + 254L)
    if (blockFirst <= blockLast) blockFirst..blockLast else null
  }
  var priorityOffset = 0L
  while (hosts.size < limit) {
    var addedThisRound = false
    priorityRanges.forEach { block ->
      val value = block.first + priorityOffset
      if (value <= block.last && value != localValue && hosts.size < limit) {
        intToStandardIpv4(value)?.let(hosts::add)
        addedThisRound = true
      }
    }
    if (!addedThisRound && priorityRanges.all { block -> block.first + priorityOffset > block.last }) {
      break
    }
    priorityOffset += 1L
  }

  // If the priority neighbourhoods did not fill the cap, spread the remaining
  // slots over the declared CIDR. Mapping remote ranks before skipping the
  // handset preserves both ends and avoids losing a slot at the local IP.
  val remaining = limit - hosts.size
  if (remaining > 0) {
    val sampleCount = min(remoteHostCount, (remaining + hosts.size).toLong())
    for (rank in 0L until sampleCount) {
      val remoteRank = if (sampleCount == 1L) {
        0L
      } else {
        rank * (remoteHostCount - 1L) / (sampleCount - 1L)
      }
      val addressOffset = if (localOffset != null && remoteRank >= localOffset) {
        remoteRank + 1L
      } else {
        remoteRank
      }
      intToStandardIpv4(first + addressOffset)?.let(hosts::add)
      if (hosts.size >= limit) break
    }
  }

  // Priority and proportional samples can overlap. Fill any remaining bounded
  // slots deterministically without ever walking more than the requested cap
  // plus those overlaps.
  var fallback = first
  while (hosts.size < limit && fallback <= last) {
    if (fallback != localValue) intToStandardIpv4(fallback)?.let(hosts::add)
    fallback += 1L
  }

  return hosts.take(limit)
}

internal enum class TcpEndpointState {
  OPEN,
  REFUSED,
  NO_RESPONSE,
}

internal data class TcpEndpointProbe(
  val host: String,
  val port: Int,
  val state: TcpEndpointState,
  val transportComplete: Boolean = true,
)

internal data class TcpScanOutcome(
  val timedOut: Boolean,
  val responsiveHosts: Set<String>,
  val transportComplete: Boolean,
  val completedProbeHosts: Set<String> = responsiveHosts,
  val activelyStimulatedHosts: Set<String> = completedProbeHosts,
)

internal data class TcpProbeTarget(
  val host: String,
  val port: Int,
)

internal fun buildFairTcpProbeTargets(
  hosts: List<String>,
  ports: List<Int>,
): List<TcpProbeTarget> = ports.flatMap { port ->
  hosts.map { host -> TcpProbeTarget(host, port) }
}

internal fun isNeighborCoverageComplete(
  beforeSourceAvailable: Boolean,
  afterSourceAvailable: Boolean,
  beforeEntryCount: Int,
  afterEntryCount: Int,
  acceptedEntryCount: Int = afterEntryCount,
  suppressedEntryCount: Int = 0,
  candidateStimulationComplete: Boolean = true,
): Boolean =
  beforeSourceAvailable &&
    afterSourceAvailable &&
    candidateStimulationComplete &&
    beforeEntryCount >= 0 &&
    afterEntryCount > 0 &&
    acceptedEntryCount > 0 &&
    suppressedEntryCount == 0

internal fun scanCoverageComplete(
  candidateCoverageComplete: Boolean,
  tcpScanOutcome: TcpScanOutcome,
  bindingRequiresPartialScan: Boolean,
  observationCapExceeded: Boolean,
): Boolean {
  // Modern Android may withhold both /proc/net/arp and `ip neigh` while every
  // bound candidate/TCP path still ran to completion. Neighbour availability
  // remains diagnostic evidence; it is not itself an execution-completeness
  // requirement. Real sampling, timeout, transport/binding, or cap loss is.
  return candidateCoverageComplete &&
    !tcpScanOutcome.timedOut &&
    tcpScanOutcome.transportComplete &&
    !bindingRequiresPartialScan &&
    !observationCapExceeded
}

/**
 * Classify transport failures without exposing their raw text. A timeout or
 * an explicit per-host negative result means that host/port pair was covered.
 * Wi-Fi/interface/socket state failures and unknown exceptions mean the scan
 * transport itself was incomplete and must hold the score.
 */
internal fun classifyTcpEndpointFailure(
  host: String,
  port: Int,
  error: Throwable,
): TcpEndpointProbe {
  val detail = error.message.orEmpty().uppercase(Locale.US)
  val localTransportFailure = listOf(
    "ENETDOWN",
    "NETWORK IS DOWN",
    "ENETUNREACH",
    "NETWORK IS UNREACHABLE",
    "EADDRNOTAVAIL",
    "CANNOT ASSIGN REQUESTED ADDRESS",
    "ENODEV",
    "NO SUCH DEVICE",
    "EBADF",
    "BAD FILE DESCRIPTOR",
    "SOCKET CLOSED",
  ).any(detail::contains)
  if (localTransportFailure) {
    return TcpEndpointProbe(
      host,
      port,
      TcpEndpointState.NO_RESPONSE,
      transportComplete = false,
    )
  }

  val refused = error is java.net.ConnectException && (
    detail.contains("ECONNREFUSED") || detail.contains("CONNECTION REFUSED")
  )
  if (refused) {
    return TcpEndpointProbe(host, port, TcpEndpointState.REFUSED)
  }

  val expectedPeerNegative =
    error is java.net.SocketTimeoutException ||
      error is java.net.NoRouteToHostException ||
      listOf(
        "EHOSTUNREACH",
        "NO ROUTE TO HOST",
        "EHOSTDOWN",
        "HOST IS DOWN",
        "ECONNRESET",
        "CONNECTION RESET",
        "ECONNABORTED",
        "CONNECTION ABORTED",
        "ETIMEDOUT",
        "TIMED OUT",
      ).any(detail::contains)
  return TcpEndpointProbe(
    host,
    port,
    TcpEndpointState.NO_RESPONSE,
    transportComplete = expectedPeerNegative,
  )
}

/**
 * Record TCP transport evidence without promoting a refusal-only address to a
 * device. ECONNREFUSED remains a useful responsiveness/coverage signal, but it
 * can be generated by gateways, transparent proxies, or network middleware and
 * therefore cannot independently create a discovery. When another discovery
 * path already established the host, keep the refusal as supporting evidence.
 */
internal fun recordTcpEndpointProbe(
  result: TcpEndpointProbe,
  discoveries: MutableMap<String, MutableDevice>,
  responsiveHosts: MutableSet<String>,
  refusedHosts: MutableSet<String>,
): Boolean {
  when (result.state) {
    TcpEndpointState.OPEN -> {
      responsiveHosts.add(result.host)
      val device = getOrCreateObservation(
        discoveries,
        result.host,
        ObservationPriority.TCP_ONLY,
      ) ?: return result.transportComplete
      device.discoverySources.add("tcp-port-probe")
      if (result.host in refusedHosts) {
        device.discoverySources.add("tcp-refused-presence")
      }
      device.openPorts.add(result.port)
      // A port number names only a TCP transport endpoint. Semantic services
      // such as ONVIF/UPnP/SMB are added only after their protocol responds.
      device.services.add("tcp-${result.port}")
    }
    TcpEndpointState.REFUSED -> {
      responsiveHosts.add(result.host)
      refusedHosts.add(result.host)
      discoveries[result.host]?.discoverySources?.add("tcp-refused-presence")
    }
    TcpEndpointState.NO_RESPONSE -> Unit
  }
  return result.transportComplete
}

internal fun tcpProbeConfirmsDevicePresence(result: TcpEndpointProbe): Boolean =
  result.state == TcpEndpointState.OPEN

internal data class ArpObservationSelection(
  val acceptedHosts: Set<String>,
  val suppressedStaleHosts: Set<String>,
)

/**
 * Parse only complete ARP neighbours from the active Wi-Fi interface. Android
 * can retain same-CIDR rows for VPNs or a previously used interface, so subnet
 * membership by itself is not an ownership signal.
 */
internal fun parseArpTableForInterface(
  lines: List<String>,
  expectedInterface: String?,
): Map<String, String> {
  val activeInterface = expectedInterface?.trim()?.takeIf { it.isNotEmpty() } ?: return emptyMap()
  return lines.drop(1).mapNotNull { line ->
    val columns = line.trim().split(Regex("\\s+"))
    val ip = columns.getOrNull(0)
    val flags = columns.getOrNull(2)
      ?.removePrefix("0x")
      ?.toIntOrNull(16)
      ?: 0
    val mac = columns.getOrNull(3)?.uppercase()
    val device = columns.getOrNull(5)
    if (
      ip != null &&
      device == activeInterface &&
      flags and 0x2 != 0 &&
      mac != null &&
      mac.matches(Regex("([0-9A-F]{2}:){5}[0-9A-F]{2}"))
    ) {
      ip to mac
    } else {
      null
    }
  }.toMap()
}

/**
 * Parse Linux/Android `ip neigh show dev <interface>` output without
 * accepting rows from another interface or failed/incomplete neighbours.
 * Examples accepted:
 *   192.168.0.1 dev wlan0 lladdr AA:BB:CC:DD:EE:FF STALE
 *   192.168.0.2 dev wlan0 lladdr 11:22:33:44:55:66 REACHABLE
 */
internal data class ParsedIpNeighborTable(
  val entries: Map<String, String>,
  val freshStateHosts: Set<String>,
)

internal fun parseIpNeighborSnapshotForInterface(
  lines: List<String>,
  expectedInterface: String?,
): ParsedIpNeighborTable {
  val activeInterface = expectedInterface?.trim()?.takeIf { it.isNotEmpty() }
    ?: return ParsedIpNeighborTable(emptyMap(), emptySet())
  val macPattern = Regex("([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")
  // Only REACHABLE means the kernel has recently confirmed bidirectional L2
  // reachability. DELAY and PROBE merely mean validation is pending and must
  // not revive a stale cache row by themselves.
  val freshStates = setOf("REACHABLE")
  val entries = linkedMapOf<String, String>()
  val freshStateHosts = linkedSetOf<String>()
  lines.forEach { line ->
    val columns = line.trim().split(Regex("\\s+"))
    val ip = columns.firstOrNull()?.takeIf { parseStandardIpv4(it) != null }
    val interfaceIndex = columns.indexOf("dev")
    // Android's `/system/bin/ip neigh show dev wlan0` is already scoped but
    // omits the `dev wlan0` tokens in its output on some builds.  Treat a
    // missing token as the interface explicitly supplied to ProcessBuilder;
    // rows that do carry `dev` must still match it exactly.
    val interfaceName = if (interfaceIndex >= 0) {
      columns.getOrNull(interfaceIndex + 1)
    } else {
      activeInterface
    }
    val macIndex = columns.indexOf("lladdr")
    val mac = columns.getOrNull(macIndex + 1)
    val neighborState = columns.lastOrNull()?.uppercase(Locale.US)
    if (
      ip != null &&
      interfaceName == activeInterface &&
      mac != null &&
      macPattern.matches(mac) &&
      !mac.equals("00:00:00:00:00:00", ignoreCase = true) &&
      !mac.equals("FF:FF:FF:FF:FF:FF", ignoreCase = true) &&
      neighborState !in setOf("FAILED", "INCOMPLETE")
    ) {
      entries[ip] = mac.uppercase(Locale.US)
      if (neighborState in freshStates) freshStateHosts.add(ip)
    }
  }
  return ParsedIpNeighborTable(entries, freshStateHosts)
}

internal fun parseIpNeighborTableForInterface(
  lines: List<String>,
  expectedInterface: String?,
): Map<String, String> = parseIpNeighborSnapshotForInterface(lines, expectedInterface).entries

/**
 * A pre-existing ARP row may be stale even when it survives the full scan.
 * Promote it only when the scan created/changed the row or collected a current
 * response from that host through a captured-Wi-Fi discovery path during this
 * run. This includes mDNS, SSDP, ONVIF, and unicast endpoint responses. An
 * unchanged row with no current response remains stale and is not published.
 */
internal fun selectFreshArpObservations(
  beforeProbe: Map<String, String>,
  afterProbe: Map<String, String>,
  candidateHosts: Set<String>,
  trustedCurrentEvidenceHosts: Set<String>,
  activelyStimulatedHosts: Set<String> = emptySet(),
  freshNeighborStateHosts: Set<String> = emptySet(),
  localIp: String,
): ArpObservationSelection {
  val accepted = linkedSetOf<String>()
  val suppressed = linkedSetOf<String>()
  afterProbe.forEach { (host, mac) ->
    if (host == localIp || host !in candidateHosts) return@forEach
    val isNewOrChanged = beforeProbe[host] != mac
    val hasCurrentPresenceEvidence =
      host in trustedCurrentEvidenceHosts ||
        host in activelyStimulatedHosts ||
        host in freshNeighborStateHosts
    if (isNewOrChanged || hasCurrentPresenceEvidence) {
      accepted.add(host)
    } else {
      suppressed.add(host)
    }
  }
  return ArpObservationSelection(
    acceptedHosts = accepted,
    suppressedStaleHosts = suppressed,
  )
}

private data class Ipv4Range(val first: Long, val last: Long)

/**
 * Single source of truth for which IPv4 observations belong to the Wi-Fi that
 * is active when the scan starts. "Private" alone is insufficient: stale ARP
 * rows and multicast replies from another routed private range must not become
 * household-device candidates.
 */
private class ActiveSubnetAllowlist private constructor(
  private val range: Ipv4Range,
  private val hostResolver: (String) -> List<InetAddress>,
) {
  private val rejectedObservations = java.util.concurrent.atomic.AtomicInteger(0)

  fun contains(ipAddress: String?): Boolean {
    val value = ipAddress?.let(::parseStandardIpv4) ?: return false
    return value in range.first..range.last
  }

  fun acceptObservation(ipAddress: String?): Boolean {
    // This scanner's declared boundary is IPv4. IPv6/link-local responses
    // are unsupported evidence for that boundary, not foreign IPv4 devices;
    // ignore them without poisoning the completed IPv4 coverage count.
    val value = ipAddress?.let(::parseStandardIpv4) ?: return false
    val allowed = value in range.first..range.last
    if (!allowed) rejectedObservations.incrementAndGet()
    return allowed
  }

  fun rejectedObservationCount(): Int = rejectedObservations.get()

  /**
   * Resolve an advertised hostname once, require every IPv4 answer to stay in
   * the active subnet, and return an allowed literal address for the socket.
   */
  fun resolveAllowedHost(host: String): String? {
    if (parseStandardIpv4(host) != null) {
      return host.takeIf(::acceptObservation)
    }
    val addresses = try {
      // Network.getAllByName is supplied by the active Wi-Fi snapshot. Never
      // use the process-default DNS resolver, which may point at a VPN.
      hostResolver(host)
        .mapNotNull { it.hostAddress }
        .filter { parseStandardIpv4(it) != null }
        .distinct()
    } catch (_: Exception) {
      emptyList()
    }
    if (addresses.isEmpty() || addresses.any { !contains(it) }) {
      rejectedObservations.incrementAndGet()
      return null
    }
    return addresses.first()
  }

  fun resolveAllowedHttpHost(location: String): String? {
    val endpoint = try {
      java.net.URI(location)
    } catch (_: Exception) {
      return null
    }
    if (!endpoint.scheme.equals("http", ignoreCase = true) || endpoint.rawUserInfo != null) {
      return null
    }
    val host = endpoint.host?.takeIf { it.isNotBlank() } ?: return null
    return resolveAllowedHost(host)
  }

  companion object {
    fun from(
      subnetCidr: String?,
      hostResolver: (String) -> List<InetAddress>,
    ): ActiveSubnetAllowlist? {
      val range = ipv4RangeFromCidr(subnetCidr) ?: return null
      return ActiveSubnetAllowlist(range, hostResolver)
    }
  }
}

private fun hostCountFromCidr(cidr: String?): Long? {
  val range = ipv4RangeFromCidr(cidr) ?: return null
  return (range.last - range.first + 1L).coerceAtLeast(0L)
}

private fun ipv4RangeFromCidr(cidr: String?): Ipv4Range? {
  if (cidr.isNullOrBlank()) return null
  val parts = cidr.trim().split("/")
  if (parts.size != 2) return null
  val ip = parseStandardIpv4(parts[0]) ?: return null
  val prefix = parts[1].toIntOrNull()?.takeIf { it in 1..30 } ?: return null
  val mask = (0xffffffffL shl (32 - prefix)) and 0xffffffffL
  val network = ip and mask
  val broadcast = network or (mask xor 0xffffffffL)
  return Ipv4Range(network + 1L, broadcast - 1L)
}

private fun parseStandardIpv4(ip: String): Long? {
  val parts = ip.trim().split(".").map { it.toIntOrNull() }
  if (parts.size != 4 || parts.any { it == null || it !in 0..255 }) return null
  return parts.fold(0L) { value, part -> (value shl 8) or part!!.toLong() }
}

private fun intToStandardIpv4(value: Long): String? {
  if (value !in 0L..0xffffffffL) return null
  return listOf(
    (value shr 24) and 0xff,
    (value shr 16) and 0xff,
    (value shr 8) and 0xff,
    value and 0xff,
  ).joinToString(".")
}

/**
 * Production logcat receives aggregate scan health only. Discovery
 * fingerprints remain in the private scan payload for server-side identity
 * resolution, but arbitrary mDNS TXT/UPnP values, names, addresses, serials,
 * identifiers, SSIDs, and tokens can never flow through this formatter.
 */
internal fun scanCompletionLog(
  durationMillis: Long,
  diagnostics: Map<String, Any?>,
): String {
  fun count(key: String): Long = (diagnostics[key] as? Number)?.toLong() ?: -1L
  fun flag(key: String): Boolean = diagnostics[key] as? Boolean ?: false

  return "scan completed duration_ms=${durationMillis.coerceAtLeast(0L)} " +
    "candidate_hosts=${count("candidate_host_count")} " +
    "subnet_hosts=${count("subnet_host_count")} " +
    "candidate_coverage_complete=${flag("candidate_coverage_complete")} " +
    "wifi_iface=${diagnostics["wifi_interface_name"] as? String ?: "none"} " +
    "arp_before=${count("arp_entries_before_probe")} " +
    "arp_after=${count("arp_entries_after_probe")} " +
    "mdns=${count("mdns_hosts")} " +
    "mdns_raw=${count("mdns_raw_hosts")} " +
    "ssdp=${count("ssdp_hosts")} " +
    "onvif=${count("onvif_hosts")} " +
    "tcp=${count("tcp_hosts")} " +
    "tcp_transport_complete=${flag("tcp_transport_complete")} " +
    "observation_limit_reached=${flag("observation_limit_reached")} " +
    "observation_dropped=${count("observation_hosts_dropped")} " +
    "observation_evicted=${count("observation_hosts_evicted")} " +
    "coverage_complete=${flag("coverage_complete")} " +
    "physical_mac_hosts=${count("physical_mac_hosts")} " +
    "manufacturer_hint_hosts=${count("manufacturer_hint_hosts")} " +
    "model_hint_hosts=${count("model_hint_hosts")} " +
    "raw_observations=${count("raw_observation_count")}"
}

internal data class SafeScanFailure(
  val code: String,
  val message: String,
)

/** Only allowlisted codes and fixed resident-facing Korean messages cross the bridge. */
internal fun safeScanFailure(code: String?): SafeScanFailure {
  return when (code) {
    "SCAN_ACTUAL_DEVICE_REQUIRED" -> SafeScanFailure(
      "SCAN_ACTUAL_DEVICE_REQUIRED",
      "현재 휴대전화에서는 공유기 점검을 실행할 수 없습니다. Wi-Fi에 연결된 휴대전화에서 다시 시도해 주세요.",
    )
    "NETWORK_NOT_SCANNABLE" -> SafeScanFailure(
      "NETWORK_NOT_SCANNABLE",
      "가정용 Wi-Fi 연결을 확인한 뒤 다시 점검해 주세요.",
    )
    "ACTIVE_WIFI_NETWORK_MISSING" -> SafeScanFailure(
      "ACTIVE_WIFI_NETWORK_MISSING",
      "현재 Wi-Fi 연결을 확인하지 못했습니다. Wi-Fi를 다시 연결한 뒤 점검해 주세요.",
    )
    "LOCAL_IP_MISSING", "LOCAL_SUBNET_MISSING" -> SafeScanFailure(
      code,
      "현재 Wi-Fi 정보를 확인하지 못했습니다. Wi-Fi를 다시 연결한 뒤 점검해 주세요.",
    )
    else -> SafeScanFailure(
      "SCAN_FAILED",
      "공유기 점검을 마치지 못했습니다. Wi-Fi 연결을 확인한 뒤 다시 시도해 주세요.",
    )
  }
}

private fun cleanSsid(ssid: String?): String? {
  if (ssid.isNullOrBlank() || ssid == "<unknown ssid>") return null
  return ssid.trim('"')
}

private fun currentUtcTimestamp(): String {
  return SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US).apply {
    timeZone = TimeZone.getTimeZone("UTC")
  }.format(Date())
}

private fun isPrivateIpv4(ip: String): Boolean {
  val parts = ip.split(".").mapNotNull { it.toIntOrNull() }
  if (parts.size != 4) return false
  return parts[0] == 10 ||
    parts[0] == 172 && parts[1] in 16..31 ||
    parts[0] == 192 && parts[1] == 168
}

private fun virtualNetworkReason(
  localIp: String?,
  gatewayIp: String?,
  subnet: String?,
  emulatorReason: String?
): String? {
  if (emulatorReason != null) return emulatorReason
  if (isAndroidVirtualIpv4(localIp)) return "android-virtual-local-ip:$localIp"
  if (isAndroidVirtualIpv4(gatewayIp)) return "android-virtual-gateway:$gatewayIp"
  if (subnet == "10.0.2.0/24" || subnet == "10.0.3.0/24") return "android-virtual-subnet:$subnet"
  return null
}

private fun isAndroidVirtualIpv4(ip: String?): Boolean {
  if (ip.isNullOrBlank()) return false
  return ip.startsWith("10.0.2.") || ip.startsWith("10.0.3.")
}

private fun emulatorReason(): String? {
  val fingerprint = Build.FINGERPRINT.lowercase()
  val model = Build.MODEL.lowercase()
  val manufacturer = Build.MANUFACTURER.lowercase()
  val brand = Build.BRAND.lowercase()
  val device = Build.DEVICE.lowercase()
  val product = Build.PRODUCT.lowercase()
  val hardware = Build.HARDWARE.lowercase()

  return when {
    fingerprint.startsWith("generic") -> "android-emulator-fingerprint"
    "emulator" in fingerprint -> "android-emulator-fingerprint"
    "sdk_gphone" in product || "sdk" in product -> "android-emulator-product"
    "emulator" in model || "android sdk built for x86" in model -> "android-emulator-model"
    "genymotion" in manufacturer -> "android-emulator-manufacturer"
    brand.startsWith("generic") && device.startsWith("generic") -> "android-emulator-device"
    "goldfish" in hardware || "ranchu" in hardware -> "android-emulator-hardware"
    else -> null
  }
}
