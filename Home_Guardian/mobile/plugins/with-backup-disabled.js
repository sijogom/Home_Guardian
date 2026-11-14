const { withAndroidManifest, withDangerousMod } = require("@expo/config-plugins");
const fs = require("fs");
const path = require("path");

// 이전 빌드의 AsyncStorage stale user 가 Google Cloud 자동 백업으로 다시 살아나는
// 경로를 차단하기 위해 application 태그에 allowBackup="false" + 백업 규칙 두 파일을 등록한다.
// mobile/android/ 폴더 자체는 .gitignore 차단 대상이라 native 파일 직접 수정만으로는
// 다음 expo prebuild 후 사라지므로, config plugin 으로 매 prebuild 시 자동 적용되도록 한다.

const BACKUP_RULES_XML = `<?xml version="1.0" encoding="utf-8"?>
<full-backup-content>
  <exclude domain="root" path="." />
  <exclude domain="file" path="." />
  <exclude domain="database" path="." />
  <exclude domain="sharedpref" path="." />
  <exclude domain="external" path="." />
</full-backup-content>
`;

const DATA_EXTRACTION_RULES_XML = `<?xml version="1.0" encoding="utf-8"?>
<data-extraction-rules>
  <cloud-backup>
    <exclude domain="root" path="." />
    <exclude domain="file" path="." />
    <exclude domain="database" path="." />
    <exclude domain="sharedpref" path="." />
    <exclude domain="external" path="." />
  </cloud-backup>
  <device-transfer>
    <exclude domain="root" path="." />
    <exclude domain="file" path="." />
    <exclude domain="database" path="." />
    <exclude domain="sharedpref" path="." />
    <exclude domain="external" path="." />
  </device-transfer>
</data-extraction-rules>
`;

function withBackupDisabledManifest(config) {
  return withAndroidManifest(config, (cfg) => {
    const application = cfg.modResults.manifest.application?.[0];
    if (application) {
      application.$["android:allowBackup"] = "false";
      application.$["android:fullBackupContent"] = "@xml/backup_rules";
      application.$["android:dataExtractionRules"] = "@xml/data_extraction_rules";
    }
    return cfg;
  });
}

function withBackupRulesXml(config) {
  return withDangerousMod(config, [
    "android",
    async (cfg) => {
      const xmlDir = path.join(
        cfg.modRequest.platformProjectRoot,
        "app",
        "src",
        "main",
        "res",
        "xml",
      );
      fs.mkdirSync(xmlDir, { recursive: true });
      fs.writeFileSync(path.join(xmlDir, "backup_rules.xml"), BACKUP_RULES_XML);
      fs.writeFileSync(path.join(xmlDir, "data_extraction_rules.xml"), DATA_EXTRACTION_RULES_XML);
      return cfg;
    },
  ]);
}

module.exports = function withBackupDisabled(config) {
  config = withBackupDisabledManifest(config);
  config = withBackupRulesXml(config);
  return config;
};
