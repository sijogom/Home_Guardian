package expo.modules.homeguardiannetworkscanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ArpFreshnessTest {
  @Test
  fun `only an open endpoint confirms TCP device presence`() {
    assertTrue(
      tcpProbeConfirmsDevicePresence(
        TcpEndpointProbe("192.168.0.20", 443, TcpEndpointState.OPEN),
      ),
    )
    assertFalse(
      tcpProbeConfirmsDevicePresence(
        TcpEndpointProbe("192.168.0.21", 443, TcpEndpointState.REFUSED),
      ),
    )
    assertFalse(
      tcpProbeConfirmsDevicePresence(
        TcpEndpointProbe("192.168.0.22", 443, TcpEndpointState.NO_RESPONSE),
      ),
    )
  }

  @Test
  fun `scan completion log never emits discovery evidence or sensitive strings`() {
    val sensitiveValues = listOf(
      "mdns-txt:serial=SN-123456",
      "mdns-txt:token=secret-token",
      "AA:BB:CC:DD:EE:FF",
      "192.168.0.44",
      "Resident-WiFi",
    )
    val log = scanCompletionLog(
      durationMillis = 321L,
      diagnostics = mapOf(
        "candidate_host_count" to 253,
        "subnet_host_count" to 254L,
        "candidate_coverage_complete" to true,
        "arp_entries_before_probe" to 3,
        "arp_entries_after_probe" to 5,
        "mdns_hosts" to 2,
        "mdns_raw_hosts" to 1,
        "ssdp_hosts" to 1,
        "onvif_hosts" to 0,
        "tcp_hosts" to 4,
        "tcp_transport_complete" to true,
        "coverage_complete" to true,
        "raw_observation_count" to 6,
        "evidence" to sensitiveValues,
        "ssid" to sensitiveValues.last(),
      ),
    )

    assertTrue(log.startsWith("scan completed duration_ms=321 candidate_hosts=253"))
    assertTrue(log.contains("candidate_coverage_complete=true"))
    assertTrue(log.contains("tcp_transport_complete=true"))
    assertTrue(log.contains("coverage_complete=true"))
    assertEquals(1, Regex("(?<!candidate_)coverage_complete=").findAll(log).count())
    assertTrue(log.endsWith("raw_observations=6"))
    sensitiveValues.forEach { sensitive -> assertFalse(log.contains(sensitive)) }
    assertFalse(log.contains("evidence="))
    assertFalse(log.contains("ssid="))
  }

  @Test
  fun `only allowlisted fixed messages cross the native failure boundary`() {
    val sensitive = "socket failed at 192.168.0.44 token=secret path=/data/user/0/app"
    val unknown = safeScanFailure(sensitive)

    assertEquals("SCAN_FAILED", unknown.code)
    assertFalse(unknown.message.contains("socket", ignoreCase = true))
    assertFalse(unknown.message.contains("192.168.0.44"))
    assertFalse(unknown.message.contains("secret"))
    assertFalse(unknown.message.contains("/data/"))

    val knownCodes = listOf(
      "SCAN_ACTUAL_DEVICE_REQUIRED",
      "NETWORK_NOT_SCANNABLE",
      "ACTIVE_WIFI_NETWORK_MISSING",
      "LOCAL_IP_MISSING",
      "LOCAL_SUBNET_MISSING",
    )
    knownCodes.forEach { code ->
      val failure = safeScanFailure(code)
      assertEquals(code, failure.code)
      assertTrue(failure.message.isNotBlank())
      assertFalse(failure.message.contains("Expo Go", ignoreCase = true))
      assertFalse(failure.message.contains("native module", ignoreCase = true))
      assertFalse(failure.message.contains("development", ignoreCase = true))
      assertFalse(failure.message.contains("release", ignoreCase = true))
    }
  }

  @Test
  fun `local TCP transport failures hold coverage while peer negatives do not`() {
    val host = "192.168.0.40"
    val localFailures = listOf(
      java.net.ConnectException("ENETDOWN (Network is down)"),
      java.net.ConnectException("ENETUNREACH (Network is unreachable)"),
      java.net.BindException("EADDRNOTAVAIL (Cannot assign requested address)"),
      IllegalStateException("unexpected transport state"),
    )
    localFailures.forEach { error ->
      val probe = classifyTcpEndpointFailure(host, 80, error)
      assertEquals(TcpEndpointState.NO_RESPONSE, probe.state)
      assertFalse(probe.transportComplete)
      assertFalse(
        scanCoverageComplete(
          candidateCoverageComplete = true,
          tcpScanOutcome = TcpScanOutcome(false, emptySet(), probe.transportComplete),
          bindingRequiresPartialScan = false,
          observationCapExceeded = false,
        ),
      )
    }

    val refused = classifyTcpEndpointFailure(
      host,
      80,
      java.net.ConnectException("ECONNREFUSED (Connection refused)"),
    )
    assertEquals(TcpEndpointState.REFUSED, refused.state)
    assertTrue(refused.transportComplete)

    val timeout = classifyTcpEndpointFailure(
      host,
      80,
      java.net.SocketTimeoutException("connect timed out"),
    )
    assertEquals(TcpEndpointState.NO_RESPONSE, timeout.state)
    assertTrue(timeout.transportComplete)
    assertTrue(
      scanCoverageComplete(
        candidateCoverageComplete = true,
        tcpScanOutcome = TcpScanOutcome(false, setOf(host), timeout.transportComplete),
        bindingRequiresPartialScan = false,
        observationCapExceeded = false,
      ),
    )
  }

  @Test
  fun `neighbor absence is diagnostic while real execution loss keeps coverage partial`() {
    val completeTcp = TcpScanOutcome(
      timedOut = false,
      responsiveHosts = emptySet(),
      transportComplete = true,
    )

    assertFalse(
      isNeighborCoverageComplete(
        beforeSourceAvailable = true,
        afterSourceAvailable = true,
        beforeEntryCount = 0,
        afterEntryCount = 0,
      ),
    )
    assertFalse(
      isNeighborCoverageComplete(
        beforeSourceAvailable = true,
        afterSourceAvailable = false,
        beforeEntryCount = 1,
        afterEntryCount = 1,
      ),
    )
    assertFalse(
      isNeighborCoverageComplete(
        beforeSourceAvailable = true,
        afterSourceAvailable = true,
        beforeEntryCount = 1,
        afterEntryCount = 0,
      ),
    )
    assertFalse(
      isNeighborCoverageComplete(
        beforeSourceAvailable = true,
        afterSourceAvailable = true,
        beforeEntryCount = 1,
        afterEntryCount = 1,
        acceptedEntryCount = 1,
        suppressedEntryCount = 0,
        candidateStimulationComplete = false,
      ),
    )
    assertFalse(
      isNeighborCoverageComplete(
        beforeSourceAvailable = true,
        afterSourceAvailable = true,
        beforeEntryCount = 2,
        afterEntryCount = 2,
        acceptedEntryCount = 1,
        suppressedEntryCount = 1,
        candidateStimulationComplete = true,
      ),
    )
    assertTrue(
      isNeighborCoverageComplete(
        beforeSourceAvailable = true,
        afterSourceAvailable = true,
        beforeEntryCount = 1,
        afterEntryCount = 1,
        acceptedEntryCount = 1,
        suppressedEntryCount = 0,
        candidateStimulationComplete = true,
      ),
    )
    assertTrue(
      scanCoverageComplete(
        candidateCoverageComplete = true,
        tcpScanOutcome = completeTcp,
        bindingRequiresPartialScan = false,
        observationCapExceeded = false,
      ),
    )
    assertFalse(
      scanCoverageComplete(
        candidateCoverageComplete = true,
        tcpScanOutcome = completeTcp,
        bindingRequiresPartialScan = true,
        observationCapExceeded = false,
      ),
    )
    assertFalse(
      scanCoverageComplete(
        candidateCoverageComplete = true,
        tcpScanOutcome = completeTcp,
        bindingRequiresPartialScan = false,
        observationCapExceeded = true,
      ),
    )
    assertFalse(
      scanCoverageComplete(
        candidateCoverageComplete = false,
        tcpScanOutcome = completeTcp,
        bindingRequiresPartialScan = false,
        observationCapExceeded = false,
      ),
    )
    assertFalse(
      scanCoverageComplete(
        candidateCoverageComplete = true,
        tcpScanOutcome = completeTcp.copy(timedOut = true),
        bindingRequiresPartialScan = false,
        observationCapExceeded = false,
      ),
    )
    assertTrue(
      scanCoverageComplete(
        candidateCoverageComplete = true,
        tcpScanOutcome = completeTcp,
        bindingRequiresPartialScan = false,
        observationCapExceeded = false,
      ),
    )
  }

  @Test
  fun `same CIDR row from another interface is rejected`() {
    val rows = listOf(
      "IP address       HW type     Flags       HW address            Mask     Device",
      "192.168.0.10     0x1         0x2         AA:BB:CC:DD:EE:10     *        wlan0",
      "192.168.0.11     0x1         0x2         AA:BB:CC:DD:EE:11     *        tun0",
      "192.168.0.12     0x1         0x0         AA:BB:CC:DD:EE:12     *        wlan0",
    )

    assertEquals(
      mapOf("192.168.0.10" to "AA:BB:CC:DD:EE:10"),
      parseArpTableForInterface(rows, "wlan0"),
    )
    assertEquals(emptyMap<String, String>(), parseArpTableForInterface(rows, null))
  }

  @Test
  fun `ip neigh fallback keeps only physical rows on active wifi interface`() {
    val rows = listOf(
      "192.168.0.1 lladdr aa:bb:cc:dd:ee:01 STALE",
      "192.168.0.2 lladdr 11:22:33:44:55:66 REACHABLE",
      "192.168.0.3 dev wlan0 FAILED",
      "192.168.0.4 dev tun0 lladdr aa:bb:cc:dd:ee:04 REACHABLE",
      "192.168.0.5 dev wlan0 lladdr 00:00:00:00:00:00 NOARP",
      "192.168.0.6 dev wlan0 lladdr aa:bb:cc:dd:ee:06 DELAY",
      "192.168.0.7 dev wlan0 lladdr aa:bb:cc:dd:ee:07 PROBE",
      "192.168.0.8 dev wlan0 lladdr aa:bb:cc:dd:ee:08 FAILED",
    )

    assertEquals(
      mapOf(
        "192.168.0.1" to "AA:BB:CC:DD:EE:01",
        "192.168.0.2" to "11:22:33:44:55:66",
        "192.168.0.6" to "AA:BB:CC:DD:EE:06",
        "192.168.0.7" to "AA:BB:CC:DD:EE:07",
      ),
      parseIpNeighborTableForInterface(rows, "wlan0"),
    )
    val parsed = parseIpNeighborSnapshotForInterface(rows, "wlan0")
    assertEquals(setOf("192.168.0.2"), parsed.freshStateHosts)
    assertEquals(emptyMap<String, String>(), parseIpNeighborTableForInterface(rows, null))
  }

  @Test
  fun `unchanged pre scan row without active evidence stays suppressed`() {
    val before = mapOf("192.168.0.10" to "AA:BB:CC:DD:EE:10")
    val after = mapOf("192.168.0.10" to "AA:BB:CC:DD:EE:10")

    val result = selectFreshArpObservations(
      beforeProbe = before,
      afterProbe = after,
      candidateHosts = setOf("192.168.0.10"),
      trustedCurrentEvidenceHosts = emptySet(),
      localIp = "192.168.0.2",
    )

    assertEquals(emptySet<String>(), result.acceptedHosts)
    assertEquals(setOf("192.168.0.10"), result.suppressedStaleHosts)
  }

  @Test
  fun `new changed or actively responsive row is accepted`() {
    val before = mapOf(
      "192.168.0.10" to "AA:BB:CC:DD:EE:10",
      "192.168.0.12" to "AA:BB:CC:DD:EE:12",
    )
    val after = mapOf(
      "192.168.0.10" to "AA:BB:CC:DD:EE:10",
      "192.168.0.11" to "AA:BB:CC:DD:EE:11",
      "192.168.0.12" to "AA:BB:CC:DD:EE:99",
    )

    val result = selectFreshArpObservations(
      beforeProbe = before,
      afterProbe = after,
      candidateHosts = after.keys,
      trustedCurrentEvidenceHosts = setOf("192.168.0.10"),
      localIp = "192.168.0.2",
    )

    assertEquals(after.keys, result.acceptedHosts)
    assertEquals(emptySet<String>(), result.suppressedStaleHosts)
  }

  @Test
  fun `current mDNS SSDP or ONVIF response preserves unchanged neighbor MAC`() {
    val staleMac = "AA:BB:CC:DD:EE:30"
    val before = mapOf("192.168.0.30" to staleMac)
    val after = mapOf("192.168.0.30" to staleMac)

    val result = selectFreshArpObservations(
      beforeProbe = before,
      afterProbe = after,
      candidateHosts = setOf("192.168.0.30"),
      trustedCurrentEvidenceHosts = setOf("192.168.0.30"),
      localIp = "192.168.0.2",
    )

    assertEquals(setOf("192.168.0.30"), result.acceptedHosts)
    assertEquals(emptySet<String>(), result.suppressedStaleHosts)
  }

  @Test
  fun `complete current candidate stimulation preserves unchanged physical MAC`() {
    val mac = "AA:BB:CC:DD:EE:31"
    val before = mapOf("192.168.0.31" to mac)
    val after = mapOf("192.168.0.31" to mac)

    val result = selectFreshArpObservations(
      beforeProbe = before,
      afterProbe = after,
      candidateHosts = setOf("192.168.0.31"),
      trustedCurrentEvidenceHosts = emptySet(),
      activelyStimulatedHosts = setOf("192.168.0.31"),
      localIp = "192.168.0.2",
    )

    assertEquals(setOf("192.168.0.31"), result.acceptedHosts)
    assertEquals(emptySet<String>(), result.suppressedStaleHosts)
  }

  @Test
  fun `partial TCP completion preserves completed neighbor without reviving unrelated stale row`() {
    val before = mapOf(
      "192.168.0.31" to "AA:BB:CC:DD:EE:31",
      "192.168.0.32" to "AA:BB:CC:DD:EE:32",
    )
    val partialTcp = TcpScanOutcome(
      timedOut = true,
      responsiveHosts = setOf("192.168.0.31"),
      transportComplete = true,
      completedProbeHosts = setOf("192.168.0.31"),
      activelyStimulatedHosts = setOf("192.168.0.31"),
    )

    val result = selectFreshArpObservations(
      beforeProbe = before,
      afterProbe = before,
      candidateHosts = before.keys,
      trustedCurrentEvidenceHosts = emptySet(),
      activelyStimulatedHosts = partialTcp.activelyStimulatedHosts,
      localIp = "192.168.0.2",
    )

    assertEquals(setOf("192.168.0.31"), result.acceptedHosts)
    assertEquals(setOf("192.168.0.32"), result.suppressedStaleHosts)
  }

  @Test
  fun `fresh ip neigh state preserves unchanged physical MAC without product clues`() {
    val mac = "AA:BB:CC:DD:EE:33"
    val before = mapOf("192.168.0.33" to mac)

    val result = selectFreshArpObservations(
      beforeProbe = before,
      afterProbe = before,
      candidateHosts = before.keys,
      trustedCurrentEvidenceHosts = emptySet(),
      freshNeighborStateHosts = setOf("192.168.0.33"),
      localIp = "192.168.0.2",
    )

    assertEquals(setOf("192.168.0.33"), result.acceptedHosts)
    val payload = MutableDevice("192.168.0.33").apply {
      discoverySources.add("android-neighbor")
    }.toPayload(arpMac = mac)
    assertEquals("AA:BB:CC:DD:EE:33", payload["mac_address"])
    assertEquals("", payload["manufacturer"])
    assertEquals("", payload["model"])
    assertEquals(emptyList<Int>(), payload["open_ports"])
  }

  @Test
  fun `port major probe order gives every host a first port before later ports`() {
    val hosts = listOf("192.168.0.2", "192.168.0.3", "192.168.0.4")
    val ports = listOf(80, 443, 445)

    val targets = buildFairTcpProbeTargets(hosts, ports)

    assertEquals(
      hosts.map { host -> TcpProbeTarget(host, 80) },
      targets.take(hosts.size),
    )
    assertEquals(hosts.size * ports.size, targets.size)
    assertEquals(targets.size, targets.toSet().size)
    assertEquals(TcpProbeTarget("192.168.0.4", 445), targets.last())
  }

  @Test
  fun `spoofed fingerprint MAC is never promoted without fresh ARP`() {
    val device = MutableDevice("192.168.0.20").apply {
      discoverySources.add("mdns")
      fingerprints.add("mdns-name:spoof [AA:BB:CC:DD:EE:20]")
    }

    val payload = device.toPayload(arpMac = null)

    assertEquals("local-192-168-0-20", payload["device_id"])
    assertFalse(payload.containsKey("mac_address"))
    assertTrue((payload["fingerprints"] as List<*>).contains("mdns-name:spoof [AA:BB:CC:DD:EE:20]"))
  }

  @Test
  fun `fresh ARP MAC wins when advertised fingerprint MAC disagrees`() {
    val device = MutableDevice("192.168.0.21").apply {
      discoverySources.add("mdns")
      fingerprints.add("mdns-name:spoof [AA:BB:CC:DD:EE:21]")
    }

    val payload = device.toPayload(arpMac = "10:20:30:40:50:60")

    assertEquals("10:20:30:40:50:60", payload["mac_address"])
    assertEquals("device-10-20-30-40-50-60", payload["device_id"])
    assertTrue((payload["fingerprints"] as List<*>).contains("mdns-name:spoof [AA:BB:CC:DD:EE:21]"))
  }

  @Test
  fun `refused TCP response stays in transport metrics without creating ARP-less device`() {
    val discoveries = mutableMapOf<String, MutableDevice>()
    val responsiveHosts = linkedSetOf<String>()
    val refusedHosts = linkedSetOf<String>()

    recordTcpEndpointProbe(
      TcpEndpointProbe("192.168.0.40", 80, TcpEndpointState.REFUSED),
      discoveries,
      responsiveHosts,
      refusedHosts,
    )

    assertEquals(setOf("192.168.0.40"), responsiveHosts)
    assertEquals(setOf("192.168.0.40"), refusedHosts)
    assertTrue(discoveries.isEmpty())
  }

  @Test
  fun `single MAC-less open port remains presence evidence without product identity`() {
    val discoveries = mutableMapOf<String, MutableDevice>()
    val responsiveHosts = linkedSetOf<String>()
    val refusedHosts = linkedSetOf<String>()

    recordTcpEndpointProbe(
      TcpEndpointProbe("192.168.0.42", 8200, TcpEndpointState.OPEN),
      discoveries,
      responsiveHosts,
      refusedHosts,
    )

    val payload = discoveries.getValue("192.168.0.42").toPayload(arpMac = null)
    assertEquals("", payload["manufacturer"])
    assertEquals("", payload["model"])
    assertEquals("unknown", payload["device_type"])
    assertEquals("enriching", payload["identity_status"])
    assertEquals(listOf(8200), payload["open_ports"])
    assertEquals(listOf("tcp-port-probe"), payload["discovery_sources"])
  }

  @Test
  fun `open TCP ports never synthesize a router computer or printer type`() {
    val cases = listOf(
      listOf(53, 80),
      listOf(139, 445),
      listOf(631, 9100),
    )

    cases.forEachIndexed { index, ports ->
      val payload = MutableDevice("192.168.0.${50 + index}").apply {
        discoverySources.add("tcp-port-probe")
        openPorts.addAll(ports)
        services.addAll(ports.map { "tcp-$it" })
      }.toPayload(arpMac = null)

      assertEquals("unknown", payload["device_type"])
      assertEquals("", payload["manufacturer"])
      assertEquals("", payload["model"])
      assertEquals("", payload["name"])
    }
  }

  @Test
  fun `TCP port 3702 is not labeled as ONVIF without a protocol response`() {
    val discoveries = mutableMapOf<String, MutableDevice>()
    recordTcpEndpointProbe(
      TcpEndpointProbe("192.168.0.70", 3702, TcpEndpointState.OPEN),
      discoveries,
      linkedSetOf(),
      linkedSetOf(),
    )

    val payload = discoveries.getValue("192.168.0.70").toPayload(null)
    assertEquals(listOf("tcp-3702"), payload["services"])
    assertEquals("unknown", payload["device_type"])
  }

  @Test
  fun `multiple TCP outcomes for one IP merge into one observation`() {
    val discoveries = mutableMapOf<String, MutableDevice>()
    val responsiveHosts = linkedSetOf<String>()
    val refusedHosts = linkedSetOf<String>()
    val host = "192.168.0.41"

    recordTcpEndpointProbe(
      TcpEndpointProbe(host, 80, TcpEndpointState.REFUSED),
      discoveries,
      responsiveHosts,
      refusedHosts,
    )
    assertTrue(discoveries.isEmpty())
    recordTcpEndpointProbe(
      TcpEndpointProbe(host, 443, TcpEndpointState.OPEN),
      discoveries,
      responsiveHosts,
      refusedHosts,
    )

    assertEquals(1, discoveries.size)
    assertEquals(setOf(host), responsiveHosts)
    val device = discoveries.getValue(host)
    assertEquals(setOf(443), device.openPorts)
    assertEquals(setOf("tcp-443"), device.services)
    assertEquals(setOf("tcp-port-probe", "tcp-refused-presence"), device.discoverySources)
  }
}
