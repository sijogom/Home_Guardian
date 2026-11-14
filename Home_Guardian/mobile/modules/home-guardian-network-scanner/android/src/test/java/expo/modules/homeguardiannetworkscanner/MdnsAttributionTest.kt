package expo.modules.homeguardiannetworkscanner

import java.io.ByteArrayOutputStream
import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MdnsAttributionTest {
  @Test
  fun `records for two responders are attributed through their SRV targets`() {
    val tvInstance = "Living TV._googlecast._tcp.local"
    val printerInstance = "Office Printer._ipp._tcp.local"
    val packet = dnsPacket(
      txt(printerInstance, "ty=Laser Printer"),
      ipv4("living-tv.local", "192.168.0.21"),
      ptr("_googlecast._tcp.local", tvInstance),
      srv(tvInstance, 8009, "living-tv.local"),
      ptr("_ipp._tcp.local", printerInstance),
      srv(printerInstance, 631, "office-printer.local"),
      ipv4("office-printer.local", "192.168.0.22"),
      txt(tvInstance, "md=Chromecast Ultra"),
      txt("Unrelated._airplay._tcp.local", "model=MustNotLeak"),
    )

    val byIp = parseMdnsAttributions(packet, "192.168.0.1").associateBy { it.ipAddress }

    assertEquals(setOf("192.168.0.21", "192.168.0.22"), byIp.keys)
    assertEquals(setOf(8009), byIp.getValue("192.168.0.21").ports)
    assertTrue(byIp.getValue("192.168.0.21").fingerprints.contains("mdns-name:$tvInstance"))
    assertTrue(byIp.getValue("192.168.0.21").fingerprints.contains("mdns-txt:md=Chromecast Ultra"))
    assertFalse(byIp.getValue("192.168.0.21").fingerprints.any { "Printer" in it || "MustNotLeak" in it })

    assertEquals(setOf(631), byIp.getValue("192.168.0.22").ports)
    assertTrue(byIp.getValue("192.168.0.22").fingerprints.contains("mdns-name:$printerInstance"))
    assertTrue(byIp.getValue("192.168.0.22").fingerprints.contains("mdns-txt:ty=Laser Printer"))
    assertFalse(byIp.getValue("192.168.0.22").fingerprints.any { "Chromecast" in it || "MustNotLeak" in it })
    assertFalse(byIp.containsKey("192.168.0.1"))
  }

  @Test
  fun `identical model evidence on distinct advertised addresses remains distinct`() {
    val firstInstance = "Classroom Display A._googlecast._tcp.local"
    val secondInstance = "Classroom Display B._googlecast._tcp.local"
    val packet = dnsPacket(
      ptr("_googlecast._tcp.local", firstInstance),
      srv(firstInstance, 8009, "display-a.local"),
      txt(firstInstance, "md=Shared Classroom Panel"),
      ipv4("display-a.local", "192.168.0.31"),
      ptr("_googlecast._tcp.local", secondInstance),
      srv(secondInstance, 8009, "display-b.local"),
      txt(secondInstance, "md=Shared Classroom Panel"),
      ipv4("display-b.local", "192.168.0.32"),
    )

    val result = parseMdnsAttributions(packet, "192.168.0.1")

    assertEquals(setOf("192.168.0.31", "192.168.0.32"), result.map { it.ipAddress }.toSet())
    result.forEach { attribution ->
      assertEquals(setOf(8009), attribution.ports)
      assertTrue(attribution.fingerprints.contains("mdns-txt:md=Shared Classroom Panel"))
    }
  }

  @Test
  fun `multiple targets without addresses never flatten onto udp source`() {
    val firstInstance = "First._http._tcp.local"
    val secondInstance = "Second._http._tcp.local"
    val packet = dnsPacket(
      ptr("_http._tcp.local", firstInstance),
      srv(firstInstance, 80, "first.local"),
      txt(firstInstance, "model=First"),
      ptr("_http._tcp.local", secondInstance),
      srv(secondInstance, 8080, "second.local"),
      txt(secondInstance, "model=Second"),
    )

    assertTrue(parseMdnsAttributions(packet, "192.168.0.44").isEmpty())
  }

  @Test
  fun `single target without address may use udp source fallback`() {
    val instance = "Family Room._spotify-connect._tcp.local"
    val packet = dnsPacket(
      ptr("_spotify-connect._tcp.local", instance),
      srv(instance, 1400, "family-room.local"),
      txt(instance, "CPath=/spotifyzc", "VERSION=1.0"),
    )

    val result = parseMdnsAttributions(packet, "192.168.0.45")

    assertEquals(1, result.size)
    assertEquals("192.168.0.45", result.single().ipAddress)
    assertEquals(setOf(1400), result.single().ports)
    assertTrue(result.single().fingerprints.contains("mdns-txt:CPath=/spotifyzc"))
  }

  @Test
  fun `AAAA address is attributed through the same service graph`() {
    val instance = "IPv6 Speaker._raop._tcp.local"
    val expectedAddress = InetAddress.getByName("fd00::21").hostAddress
    val packet = dnsPacket(
      ptr("_raop._tcp.local", instance),
      srv(instance, 7000, "speaker.local"),
      txt(instance, "am=SpeakerModel"),
      ipv6("speaker.local", "fd00::21"),
    )

    val result = parseMdnsAttributions(packet, "192.168.0.1")

    assertEquals(listOf(expectedAddress), result.map { it.ipAddress })
    assertEquals(setOf(7000), result.single().ports)
    assertTrue(result.single().fingerprints.contains("mdns-txt:am=SpeakerModel"))
  }

  private data class DnsRecord(
    val owner: String,
    val type: Int,
    val payload: ByteArray,
  )

  private fun dnsPacket(vararg records: DnsRecord): ByteArray {
    val output = ByteArrayOutputStream()
    writeShort(output, 0)
    writeShort(output, 0x8400)
    writeShort(output, 0)
    writeShort(output, records.size)
    writeShort(output, 0)
    writeShort(output, 0)
    records.forEach { record ->
      output.write(dnsName(record.owner))
      writeShort(output, record.type)
      writeShort(output, 0x8001)
      writeInt(output, 120)
      writeShort(output, record.payload.size)
      output.write(record.payload)
    }
    return output.toByteArray()
  }

  private fun ptr(serviceType: String, instanceName: String): DnsRecord =
    DnsRecord(serviceType, 12, dnsName(instanceName))

  private fun srv(instanceName: String, port: Int, targetName: String): DnsRecord {
    val output = ByteArrayOutputStream()
    writeShort(output, 0)
    writeShort(output, 0)
    writeShort(output, port)
    output.write(dnsName(targetName))
    return DnsRecord(instanceName, 33, output.toByteArray())
  }

  private fun txt(instanceName: String, vararg values: String): DnsRecord {
    val output = ByteArrayOutputStream()
    values.forEach { value ->
      val bytes = value.toByteArray(Charsets.UTF_8)
      require(bytes.size <= 255)
      output.write(bytes.size)
      output.write(bytes)
    }
    return DnsRecord(instanceName, 16, output.toByteArray())
  }

  private fun ipv4(hostName: String, address: String): DnsRecord =
    DnsRecord(hostName, 1, InetAddress.getByName(address).address)

  private fun ipv6(hostName: String, address: String): DnsRecord =
    DnsRecord(hostName, 28, InetAddress.getByName(address).address)

  private fun dnsName(value: String): ByteArray {
    val output = ByteArrayOutputStream()
    value.trimEnd('.').split('.').forEach { label ->
      val bytes = label.toByteArray(Charsets.UTF_8)
      require(bytes.size in 1..63)
      output.write(bytes.size)
      output.write(bytes)
    }
    output.write(0)
    return output.toByteArray()
  }

  private fun writeShort(output: ByteArrayOutputStream, value: Int) {
    output.write((value ushr 8) and 0xFF)
    output.write(value and 0xFF)
  }

  private fun writeInt(output: ByteArrayOutputStream, value: Int) {
    output.write((value ushr 24) and 0xFF)
    output.write((value ushr 16) and 0xFF)
    output.write((value ushr 8) and 0xFF)
    output.write(value and 0xFF)
  }
}
