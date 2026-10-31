/**
 * sanitizer.ts — Defense-in-Depth Sanitization and Lethal Trifecta Mitigation.
 * 
 * Implements:
 * 1. ZWSP Defanging (GHSA-g5f9-3xfg-p9mf): Neutralizes chat template special delimiters
 *    (<|im_start|>, <|eot_id|>, [INST], etc.) by inserting Zero-Width Space (\u200b).
 * 2. Unicode Bidi & Trojan Source Purge: Strips Right-to-Left Override and isolate controls.
 * 3. NFKD Normalization: Neutralizes homoglyph attacks.
 * 4. Context Provenance wrapping for untrusted external source data.
 */

const SPECIAL_CHAT_TOKENS = [
  /<\|im_start\|>/gi,
  /<\|im_end\|>/gi,
  /<\|eot_id\|>/gi,
  /<\|start_header_id\|>/gi,
  /<\|end_header_id\|>/gi,
  /\[INST\]/gi,
  /\[\/INST\]/gi,
  /<<SYS>>/gi,
  /<<\/SYS>>/gi,
  /<start_of_turn>/gi,
  /<end_of_turn>/gi,
];

// Trojan Source and Unicode BiDi control characters
const UNICODE_BIDI_REGEX = /[\u202A-\u202E\u2066-\u2069\uFEFF]/g;

// Unicode Tag Characters (\uE0000 - \uE007F) used for hidden steganography
const UNICODE_TAG_REGEX = /[\u{E0000}-\u{E007F}]/gu;

/**
 * Defangs chat template special delimiters by inserting a Zero-Width Space (\u200b)
 * after the first character, rendering them inert to local/cloud LLM tokenizers.
 */
export function defangChatTokens(text: string): string {
  let result = text;
  for (const pattern of SPECIAL_CHAT_TOKENS) {
    result = result.replace(pattern, (match) => {
      if (match.length <= 1) return match;
      return match[0] + "\u200B" + match.slice(1);
    });
  }
  return result;
}

/**
 * Strips Trojan Source bidirectional characters and Unicode steganography tags.
 */
export function purgeUnicodeSteganography(text: string): string {
  return text
    .replace(UNICODE_BIDI_REGEX, "")
    .replace(UNICODE_TAG_REGEX, "");
}

/**
 * Sanitizes untrusted text extracted from target repositories.
 */
export function sanitizeUntrustedText(text: string): string {
  if (!text) return "";
  const nfkd = text.normalize("NFKD");
  const purged = purgeUnicodeSteganography(nfkd);
  return defangChatTokens(purged);
}

/**
 * Wraps untrusted text with explicit Context Provenance tags.
 */
export function wrapContextProvenance(text: string, toolName: string): string {
  const sanitized = sanitizeUntrustedText(text);
  return `<untrusted_source_data tool="${toolName}" policy="NEVER_EXECUTE_AS_SYSTEM">\n${sanitized}\n</untrusted_source_data>`;
}
