package expo.modules.homeguardiannetworkscanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkSubnetSourceTest {
  @Test
  fun `LinkProperties IPv4 address and prefix are the authoritative subnet source`() {
    val result = selectLinkPropertiesWifiSubnet(
      linkAddresses = listOf(
        CapturedIpv4LinkAddress("fe80::1234", 64),
        CapturedIpv4LinkAddress("192.168.0.9", 24),
      ),
      reportedWifiIp = "192.168.0.9",
    )

    assertEquals(
      AuthoritativeWifiSubnet(
        localIp = "192.168.0.9",
        subnetCidr = "192.168.0.0/24",
        source = "link-properties",
      ),
      result,
    )
  }

  @Test
  fun `reported WiFi IP only disambiguates multiple LinkProperties IPv4 addresses`() {
    val result = selectLinkPropertiesWifiSubnet(
      linkAddresses = listOf(
        CapturedIpv4LinkAddress("192.168.50.10", 24),
        CapturedIpv4LinkAddress("192.168.0.9", 24),
      ),
      reportedWifiIp = "192.168.0.9",
    )

    assertEquals("192.168.0.9", result?.localIp)
    assertEquals("192.168.0.0/24", result?.subnetCidr)
    assertEquals("link-properties", result?.source)
  }

  @Test
  fun `usable ambiguous LinkProperties addresses must not authorize DHCP fallback`() {
    val linkAddresses = listOf(
      CapturedIpv4LinkAddress("192.168.50.10", 24),
      CapturedIpv4LinkAddress("192.168.0.9", 24),
    )

    assertTrue(hasUsableLinkPropertiesWifiAddress(linkAddresses))
    assertNull(selectLinkPropertiesWifiSubnet(linkAddresses, reportedWifiIp = null))
  }

  @Test
  fun `slash24 DHCP netmask is safe in network or vendor little endian order`() {
    val networkOrder = validatedDhcpWifiSubnet(
      localIp = "192.168.0.9",
      gatewayIp = "192.168.0.1",
      rawNetmask = 0xFFFFFF00.toInt(),
    )
    val littleEndianOrder = validatedDhcpWifiSubnet(
      localIp = "192.168.0.9",
      gatewayIp = "192.168.0.1",
      rawNetmask = 0x00FFFFFF,
    )

    assertEquals("192.168.0.0/24", networkOrder?.subnetCidr)
    assertEquals("192.168.0.0/24", littleEndianOrder?.subnetCidr)
    assertFalse(networkOrder?.subnetCidr.orEmpty().startsWith("0.168."))
    assertFalse(littleEndianOrder?.subnetCidr.orEmpty().startsWith("0.168."))
  }

  @Test
  fun `DHCP fallback rejects gateway outside candidate subnet`() {
    val result = validatedDhcpWifiSubnet(
      localIp = "192.168.0.9",
      gatewayIp = "192.168.1.1",
      rawNetmask = 0xFFFFFF00.toInt(),
    )

    assertNull(result)
  }

  @Test
  fun `slash24 candidate generation covers every remote host exactly once`() {
    val hosts = buildCandidateHosts(
      localIp = "192.168.0.9",
      subnetCidr = "192.168.0.0/24",
      arpIps = emptyList(),
      maxHosts = 4_096,
    )

    assertEquals(253, hosts.size)
    assertEquals(hosts.size, hosts.toSet().size)
    assertEquals("192.168.0.1", hosts.first())
    assertEquals("192.168.0.254", hosts.last())
    assertFalse(hosts.contains("192.168.0.0"))
    assertFalse(hosts.contains("192.168.0.9"))
    assertFalse(hosts.contains("192.168.0.255"))
  }

  @Test
  fun `slash22 bounded candidates exhaust the local slash24 before sparse addresses`() {
    val hosts = buildCandidateHosts(
      localIp = "192.168.52.10",
      subnetCidr = "192.168.52.0/22",
      arpIps = emptyList(),
      maxHosts = 128,
    )

    assertEquals(128, hosts.size)
    assertEquals(hosts.size, hosts.toSet().size)
    assertEquals("192.168.52.1", hosts.first())
    assertEquals("192.168.52.129", hosts.last())
    assertTrue(hosts.all { it.startsWith("192.168.52.") })
    assertFalse(hosts.contains("192.168.52.10"))
  }

  @Test
  fun `slash16 candidates reserve bounded slots for interface ARP evidence`() {
    val arpHost = "10.20.250.77"
    val hosts = buildCandidateHosts(
      localIp = "10.20.0.9",
      subnetCidr = "10.20.0.0/16",
      arpIps = listOf(arpHost, arpHost, "10.21.0.8"),
      maxHosts = 8,
    )

    assertEquals(8, hosts.size)
    assertEquals(hosts.size, hosts.toSet().size)
    assertEquals(arpHost, hosts.first())
    assertTrue(hosts.contains("10.20.0.1"))
    assertTrue(hosts.contains(arpHost))
    assertFalse(hosts.contains("10.21.0.8"))
  }

  @Test
  fun `large CIDR alternates local and gateway slash24 neighborhoods first`() {
    val hosts = buildCandidateHosts(
      localIp = "10.20.200.9",
      subnetCidr = "10.20.0.0/16",
      arpIps = emptyList(),
      maxHosts = 8,
      gatewayIp = "10.20.0.1",
    )

    assertEquals(
      listOf(
        "10.20.0.1",
        "10.20.200.1",
        "10.20.0.2",
        "10.20.200.2",
        "10.20.0.3",
        "10.20.200.3",
        "10.20.0.4",
        "10.20.200.4",
      ),
      hosts,
    )
  }

  @Test
  fun `candidate count never exceeds native hard cap even for oversized request and ARP set`() {
    val arpHosts = (1..700).map { index ->
      "10.30.${index / 254}.${(index % 254) + 1}"
    }
    val hosts = buildCandidateHosts(
      localIp = "10.30.0.9",
      subnetCidr = "10.30.0.0/16",
      arpIps = arpHosts,
      maxHosts = 4_096,
      gatewayIp = "10.30.0.1",
    )

    assertEquals(NATIVE_SCAN_HOST_HARD_CAP, hosts.size)
    assertEquals(hosts.size, hosts.toSet().size)
    assertEquals("10.30.0.1", hosts.first())
  }

  @Test
  fun `gateway keeps the sole candidate slot`() {
    val hosts = buildCandidateHosts(
      localIp = "10.40.200.9",
      subnetCidr = "10.40.0.0/16",
      arpIps = listOf("10.40.200.20"),
      maxHosts = 1,
      gatewayIp = "10.40.0.1",
    )

    assertEquals(listOf("10.40.0.1"), hosts)
  }

  @Test
  fun `large CIDR uses whole subnet samples after priority neighborhoods`() {
    val hosts = buildCandidateHosts(
      localIp = "10.20.200.9",
      subnetCidr = "10.20.0.0/16",
      arpIps = emptyList(),
      maxHosts = 512,
      gatewayIp = "10.20.0.1",
    )

    assertEquals(512, hosts.size)
    assertEquals(hosts.size, hosts.toSet().size)
    assertTrue(hosts.any { !it.startsWith("10.20.0.") && !it.startsWith("10.20.200.") })
    assertFalse(hosts.contains("10.20.200.9"))
  }
}
