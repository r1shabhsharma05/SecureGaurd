/**
 * One canonical finding ID, everywhere: V-0068 (4 digits).
 * The list used V-0068, the overview used V-068 and the detail page used
 * VULN-#68 for the same row — three formats for one id.
 */
export function formatVulnId(id: number): string {
  return `V-${String(id).padStart(4, '0')}`;
}
