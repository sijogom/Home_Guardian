package expo.modules.homeguardiannetworkscanner

import org.junit.Assert.assertEquals
import org.junit.Test

class SelfDeviceTypeTest {
  @Test
  fun `Samsung tablet model families are emitted as tablet`() {
    listOf(
      "SM-T720",
      "sm-x910",
      " SM-P610 ",
    ).forEach { model ->
      assertEquals("tablet", classifySelfAndroidDeviceType(model))
    }
  }

  @Test
  fun `Samsung Fold and other Android models remain phone`() {
    listOf(
      "SM-F956N",
      "SM-S928N",
      "Pixel 9 Pro",
      "",
    ).forEach { model ->
      assertEquals("phone", classifySelfAndroidDeviceType(model))
    }
    assertEquals("phone", classifySelfAndroidDeviceType(null))
  }
}
