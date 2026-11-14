const { withAndroidManifest } = require("@expo/config-plugins");

/**
 * Release artifacts must not make an app-wide exception for cleartext HTTP.
 * The native LAN scanner uses its own raw discovery socket only for local
 * device probes; API traffic follows the Android network security policy.
 */
module.exports = function withNetworkSecurity(config) {
  return withAndroidManifest(config, (configWithManifest) => {
    const application = configWithManifest.modResults.manifest.application?.[0];
    if (application) {
      // app.config.js can allow a local development backend only after an
      // explicit opt-in. Production config always resolves to false. The
      // setting lives in Expo's schema-supported `extra` object so it does
      // not become an unsupported Android app-config property.
      application.$["android:usesCleartextTraffic"] = config.extra?.allowCleartextDevelopment === true ? "true" : "false";
    }
    return configWithManifest;
  });
};
