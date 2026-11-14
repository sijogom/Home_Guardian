package expo.modules.homeguardiannetworkscanner

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class DnsSdDynamicServiceTypeTest {
  @Test
  fun `meta query returns only valid local base service types`() {
    val packet = dnsPacket(
      ptr("_services._dns-sd._udp.local", "_vendor-camera._tcp.local"),
      ptr("_SERVICES._DNS-SD._UDP.LOCAL", "_classroom-panel._UDP.LOCAL"),
      ptr("_services._dns-sd._udp.local", "_vendor-camera._tcp.local"),
      ptr("_services._dns-sd._udp.local", "_outside._tcp.example"),
      ptr("_services._dns-sd._udp.local", "_printer._sub._tcp.local"),
      ptr("_not-the-meta-query._udp.local", "_ignored._tcp.local"),
    )

    assertEquals(
      listOf("_vendor-camera._tcp.local", "_classroom-panel._udp.local"),
      parseDnsSdServiceTypes(packet, maxTypes = 24),
    )
  }

  @Test
  fun `dynamic service type count is bounded and stable`() {
    val packet = dnsPacket(
      ptr("_services._dns-sd._udp.local", "_one._tcp.local"),
      ptr("_services._dns-sd._udp.local", "_two._tcp.local"),
      ptr("_services._dns-sd._udp.local", "_three._udp.local"),
    )

    assertEquals(listOf("_one._tcp.local", "_two._tcp.local"), parseDnsSdServiceTypes(packet, 2))
    assertEquals(emptyList<String>(), parseDnsSdServiceTypes(packet, 0))
  }

  @Test
  fun `normalizer rejects hosts subtypes non local domains and invalid transports`() {
    assertEquals("_googlecast._tcp.local", normalizeLocalDnsSdServiceType("_GoogleCast._TCP.LOCAL."))
    assertNull(normalizeLocalDnsSdServiceType("printer._tcp.local"))
    assertNull(normalizeLocalDnsSdServiceType("_printer._sub._tcp.local"))
    assertNull(normalizeLocalDnsSdServiceType("_printer._tcp.example"))
    assertNull(normalizeLocalDnsSdServiceType("_printer._quic.local"))
    assertNull(normalizeLocalDnsSdServiceType("_-printer._tcp.local"))
  }

  private fun dnsPacket(vararg records: ByteArray): ByteArray {
    val bytes = ByteArrayOutputStream()
    DataOutputStream(bytes).use { output ->
      output.writeShort(0)
      output.writeShort(0x8400)
      output.writeShort(0)
      output.writeShort(records.size)
      output.writeShort(0)
      output.writeShort(0)
      records.forEach(output::write)
    }
    return bytes.toByteArray()
  }

  private fun ptr(owner: String, target: String): ByteArray {
    val targetBytes = dnsName(target)
    val bytes = ByteArrayOutputStream()
    DataOutputStream(bytes).use { output ->
      output.write(dnsName(owner))
      output.writeShort(12)
      output.writeShort(1)
      output.writeInt(120)
      output.writeShort(targetBytes.size)
      output.write(targetBytes)
    }
    return bytes.toByteArray()
  }

  private fun dnsName(name: String): ByteArray {
    val bytes = ByteArrayOutputStream()
    name.trimEnd('.').split('.').forEach { label ->
      val encoded = label.toByteArray(Charsets.US_ASCII)
      bytes.write(encoded.size)
      bytes.write(encoded)
    }
    bytes.write(0)
    return bytes.toByteArray()
  }
}
