package expo.modules.homeguardiannetworkscanner

import java.net.DatagramSocket
import java.net.Socket
import java.net.SocketException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class WifiBoundSocketFactoryTest {
  @Test
  fun `datagram socket is unbound until authoritative network binding runs`() {
    val diagnostics = NetworkSocketBindingDiagnostics()
    val binding = RecordingBinding()
    val factory = WifiBoundSocketFactory(binding, diagnostics)

    val socket = factory.openDatagram()

    assertNotNull(socket)
    assertEquals(1, binding.datagramCalls)
    assertFalse(binding.datagramWasBoundWhenCalled)
    assertFalse(binding.datagramWasConnectedWhenCalled)
    assertFalse(socket!!.isClosed)
    assertEquals(
      NetworkSocketBindingSnapshot(1, 0, 0, 0, 0),
      diagnostics.snapshot(),
    )
    socket.close()
  }

  @Test
  fun `stream socket is unconnected until authoritative network binding runs`() {
    val diagnostics = NetworkSocketBindingDiagnostics()
    val binding = RecordingBinding()
    val factory = WifiBoundSocketFactory(binding, diagnostics)

    val socket = factory.openStream()

    assertNotNull(socket)
    assertEquals(1, binding.streamCalls)
    assertFalse(binding.streamWasBoundWhenCalled)
    assertFalse(binding.streamWasConnectedWhenCalled)
    assertFalse(socket!!.isClosed)
    socket.close()
  }

  @Test
  fun `binding failure closes socket and returns no fallback socket`() {
    val diagnostics = NetworkSocketBindingDiagnostics()
    val binding = RecordingBinding(failDatagram = true)
    val factory = WifiBoundSocketFactory(binding, diagnostics)

    val socket = factory.openDatagram()

    assertNull(socket)
    assertNotNull(binding.lastDatagram)
    assertTrue(binding.lastDatagram!!.isClosed)
    assertEquals(
      NetworkSocketBindingSnapshot(1, 1, 0, 0, 0),
      diagnostics.snapshot(),
    )
    assertTrue(diagnostics.snapshot().requiresPartialScan)
  }

  @Test
  fun `first binding failure suppresses every later socket instead of using default route`() {
    val diagnostics = NetworkSocketBindingDiagnostics()
    val binding = RecordingBinding(failDatagram = true)
    val factory = WifiBoundSocketFactory(binding, diagnostics)

    assertNull(factory.openDatagram())
    assertNull(factory.openStream())
    assertNull(factory.openMulticast())

    assertEquals(1, binding.datagramCalls)
    assertEquals(0, binding.streamCalls)
    assertEquals(
      NetworkSocketBindingSnapshot(1, 1, 2, 0, 0),
      diagnostics.snapshot(),
    )
  }

  @Test
  fun `unsupported global NSD skip is diagnostic without downgrading bound raw discovery`() {
    val diagnostics = NetworkSocketBindingDiagnostics()

    diagnostics.recordUnboundPathSkipped()

    assertEquals(
      NetworkSocketBindingSnapshot(0, 0, 0, 1, 0),
      diagnostics.snapshot(),
    )
    assertFalse(diagnostics.snapshot().requiresPartialScan)
  }

  private class RecordingBinding(
    private val failDatagram: Boolean = false,
  ) : AuthoritativeNetworkSocketBinding {
    var datagramCalls = 0
    var streamCalls = 0
    var datagramWasBoundWhenCalled = true
    var datagramWasConnectedWhenCalled = true
    var streamWasBoundWhenCalled = true
    var streamWasConnectedWhenCalled = true
    var lastDatagram: DatagramSocket? = null

    override fun bind(socket: DatagramSocket) {
      datagramCalls += 1
      lastDatagram = socket
      datagramWasBoundWhenCalled = socket.isBound
      datagramWasConnectedWhenCalled = socket.isConnected
      if (failDatagram) throw SocketException("authoritative Wi-Fi unavailable")
    }

    override fun bind(socket: Socket) {
      streamCalls += 1
      streamWasBoundWhenCalled = socket.isBound
      streamWasConnectedWhenCalled = socket.isConnected
    }
  }
}
