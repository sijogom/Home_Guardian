package expo.modules.homeguardiannetworkscanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ObservationCapacityTest {
  @Test
  fun `structured neighbor and gateway evidence replace TCP-only rows at the hard boundary`() {
    val observations = BoundedObservationMap(
      gatewayIp = "192.168.0.1",
      requestedLimit = 3,
    )
    listOf("192.168.0.10", "192.168.0.11", "192.168.0.12").forEach { host ->
      observations.observe(host, ObservationPriority.TCP_ONLY)
    }

    observations.observe("192.168.0.20", ObservationPriority.STRUCTURED_DISCOVERY)
    observations.observe("192.168.0.30", ObservationPriority.FRESH_NEIGHBOR)
    observations.observe("192.168.0.1", ObservationPriority.TCP_ONLY)
    val rejectedEqualPriority = observations.observe(
      "192.168.0.21",
      ObservationPriority.STRUCTURED_DISCOVERY,
    )

    assertEquals(3, observations.size)
    assertEquals(
      setOf("192.168.0.20", "192.168.0.30", "192.168.0.1"),
      observations.keys,
    )
    assertNull(rejectedEqualPriority)
    assertEquals(4, observations.overflowEvents)
    assertEquals(3, observations.evictedLowerPriorityHosts)
    assertEquals(1, observations.droppedHosts)
    assertTrue(observations.capacityExceeded)
  }

  @Test
  fun `requested observation limit can never exceed 512`() {
    val observations = BoundedObservationMap(
      gatewayIp = null,
      requestedLimit = 4_096,
    )

    repeat(700) { index ->
      observations.observe("10.0.${index / 250}.${index % 250 + 1}", ObservationPriority.TCP_ONLY)
    }

    assertEquals(NATIVE_SCAN_HOST_HARD_CAP, observations.hardLimit)
    assertEquals(NATIVE_SCAN_HOST_HARD_CAP, observations.size)
    assertTrue(observations.capacityExceeded)
    assertEquals(188, observations.droppedHosts)
  }

  @Test
  fun `open TCP overflow stays aggregate transport evidence without growing observations`() {
    val observations = BoundedObservationMap(gatewayIp = null, requestedLimit = 2)
    val responsive = linkedSetOf<String>()
    val refused = linkedSetOf<String>()

    repeat(3) { index ->
      recordTcpEndpointProbe(
        TcpEndpointProbe("192.168.0.${40 + index}", 80, TcpEndpointState.OPEN),
        observations,
        responsive,
        refused,
      )
    }

    assertEquals(2, observations.size)
    assertEquals(3, responsive.size)
    assertEquals(1, observations.droppedHosts)
    assertTrue(observations.capacityExceeded)
    observations.values.forEach { device ->
      assertEquals("unknown", device.toPayload(null)["device_type"])
    }
  }

  @Test
  fun `SSDP USN and UPnP UDN fingerprints are bounded private identifiers`() {
    val gatewayUuid = "11111111-2222-4333-8444-555555555555"
    assertEquals(
      "ssdp-usn:uuid:$gatewayUuid::upnp:rootdevice",
      boundedProtocolIdentityFingerprint(
        "ssdp-usn",
        " UUID:${gatewayUuid.uppercase()}::upnp:rootdevice ",
      ),
    )
    assertEquals(
      "upnp-udn:uuid:$gatewayUuid",
      boundedProtocolIdentityFingerprint("upnp-udn", "uuid:$gatewayUuid"),
    )
    assertNull(boundedProtocolIdentityFingerprint("ssdp-usn", "uuid:not-a-strong-uuid"))
    assertNull(boundedProtocolIdentityFingerprint("upnp-udn", "uuid:$gatewayUuid::service"))
    assertNull(boundedProtocolIdentityFingerprint("ssdp-usn", "x".repeat(257)))
    assertNull(boundedProtocolIdentityFingerprint("ssdp-usn", "uuid:ok\nforged"))
    assertNull(boundedProtocolIdentityFingerprint("product-model", "device-1"))

    val xml = """
      <root xmlns="urn:schemas-upnp-org:device-1-0">
        <device><upnp:UDN xmlns:upnp="urn:test">uuid:$gatewayUuid</upnp:UDN></device>
      </root>
    """.trimIndent()
    assertEquals("uuid:$gatewayUuid", extractBoundedXmlTag(xml, "UDN", 256))

    val payload = MutableDevice("192.168.0.20").apply {
      discoverySources.add("ssdp")
      fingerprints.add("ssdp-usn:uuid:$gatewayUuid::upnp:rootdevice")
      fingerprints.add("upnp-udn:uuid:$gatewayUuid")
    }.toPayload(arpMac = null)
    assertEquals("unknown", payload["device_type"])
    assertEquals("", payload["manufacturer"])
    assertEquals("", payload["model"])
    assertFalse(payload.containsKey("mac_address"))
  }

  @Test
  fun `UPnP description endpoint must match the actual SSDP response source`() {
    assertTrue(sameIpv4Endpoint("192.168.0.20", "192.168.0.20"))
    assertFalse(sameIpv4Endpoint("192.168.0.21", "192.168.0.20"))
    assertFalse(sameIpv4Endpoint("example.invalid", "192.168.0.20"))
  }

  @Test
  fun `per-device fingerprint accumulation is bounded`() {
    val device = MutableDevice("192.168.0.60")
    repeat(300) { index -> device.fingerprints.add("mdns-txt:k$index=v$index") }
    val gatewayUuid = "11111111-2222-4333-8444-555555555555"
    device.fingerprints.add("ssdp-location:http://192.168.0.60/root.xml")
    device.fingerprints.add("ssdp-usn:uuid:$gatewayUuid::upnp:rootdevice")

    assertEquals(128, device.fingerprints.size)
    assertTrue(device.fingerprints.contains("ssdp-location:http://192.168.0.60/root.xml"))
    assertTrue(device.fingerprints.contains("ssdp-usn:uuid:$gatewayUuid::upnp:rootdevice"))
  }
}
