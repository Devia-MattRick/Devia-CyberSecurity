import { z } from "zod";

/**
 * Modos de ejecución autorizados para las reglas de Reducción de Superficie de Ataque (ASR).
 */
export const AsrRuleModeSchema = z.enum([
  "DISABLED", // 0
  "BLOCK",    // 1
  "AUDIT",    // 2
  "WARN"      // 6
]);

export type AsrRuleMode = z.infer<typeof AsrRuleModeSchema>;

/**
 * Catálogo canónico de identificadores GUID para las 16 reglas ASR de Microsoft Defender.
 */
export const AsrRuleGuidSchema = z.enum([
  "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", // Block executable content from email client and webmail
  "D4F940AB-401B-4EFC-AADC-AD5F3C50688A", // Block all Office applications from creating child processes
  "3B576869-A4EC-4529-8536-B80A7769E899", // Block Office applications from creating executable content
  "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84", // Block Office applications from injecting code into other processes
  "D3E037E1-3EB8-44C8-A917-57927947596D", // Block JavaScript or VBScript from launching downloaded executable content
  "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC", // Block execution of potentially obfuscated scripts
  "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B", // Block Win32 API calls from Office macros
  "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2", // Block credential stealing from LSASS (lsass.exe)
  "D1E49AAC-8F56-4280-B9BA-993A6D77406C", // Block process creations originating from PSExec and WMI commands
  "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4", // Block untrusted and unsigned processes that run from USB
  "26190899-770F-478B-AE56-4FF587E3C9E8", // Block abuse of exploited vulnerable signed drivers
  "E6DB77E5-3DF2-4CF1-B95A-636979351E5B", // Block persistence through WMI event subscription
  "01443614-CD74-433A-B99E-2ECDC07BFC25", // Block executable files unless they meet prevalence/age criterion
  "C1DB55AB-C21A-4637-BB3F-A12568109D35", // Use advanced protection against ransomware
  "A8F58958-CBA8-4D6F-9A0E-6577B7642BF5", // Block Adobe Reader from creating child processes
  "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C"  // Block Adobe Reader from creating executable content
]);

export type AsrRuleGuid = z.infer<typeof AsrRuleGuidSchema>;

/**
 * Evaluación individual de una regla ASR.
 */
export const AsrRuleStatusSchema = z.object({
  guid: AsrRuleGuidSchema,
  name: z.string().min(5),
  currentMode: AsrRuleModeSchema,
  expectedMode: AsrRuleModeSchema,
  isCompliant: z.boolean(),
  mitreTechnique: z.string().regex(/^T\d+(\.\d+)?$/)
});

export type AsrRuleStatus = z.infer<typeof AsrRuleStatusSchema>;

/**
 * Configuración auditada de Microsoft Defender Antivirus / MDE.
 */
export const DefenderPreferencesSchema = z.object({
  realTimeProtection: z.boolean(),
  behaviorMonitoring: z.boolean(),
  ioavProtection: z.boolean(),
  networkProtection: z.enum(["DISABLED", "BLOCK", "AUDIT"]),
  controlledFolderAccess: z.enum(["DISABLED", "BLOCK", "AUDIT"]),
  cloudBlockLevel: z.enum(["DEFAULT", "HIGH", "HIGH_PLUS", "ZERO_TOLERANCE"]),
  puaProtection: z.enum(["DISABLED", "ENABLED", "AUDIT"]),
  tamperProtection: z.boolean(),
  signatureAgeHours: z.number().nonnegative().optional()
});

export type DefenderPreferences = z.infer<typeof DefenderPreferencesSchema>;

/**
 * Veredicto terminal de cumplimiento de endurecimiento de endpoint.
 */
export const EndpointAuditVerdictSchema = z.enum([
  "PASS",
  "WARN",
  "FAIL"
]);

export type EndpointAuditVerdict = z.infer<typeof EndpointAuditVerdictSchema>;

/**
 * Reporte completo y sellado de auditoría de endurecimiento de endpoint.
 */
export const EndpointHardeningReportSchema = z.object({
  reportId: z.string().uuid(),
  evaluatedAt: z.string().datetime(),
  hostId: z.string().min(1),
  osPlatform: z.enum(["WINDOWS_10", "WINDOWS_11", "WINDOWS_SERVER", "OTHER"]),
  defenderPreferences: DefenderPreferencesSchema,
  asrRules: z.array(AsrRuleStatusSchema),
  complianceScore: z.number().min(0).max(100),
  criticalGaps: z.array(z.string()),
  verdict: EndpointAuditVerdictSchema,
  remediationGuidance: z.array(z.string())
});

export type EndpointHardeningReport = z.infer<typeof EndpointHardeningReportSchema>;
