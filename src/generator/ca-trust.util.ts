/** Where the CA volume is mounted inside a generated backend container (read-only). */
export const CA_MOUNT_DIR = '/etc/backos-ca';

/**
 * How a generated backend learns to trust the BackOS API when that API serves HTTPS with the LAN stack's
 * private CA (see src/tools/lan-tls). The volume holds the CA's PUBLIC certificate only; it is mounted
 * read-only and Node is told to trust it IN ADDITION to its usual roots (NODE_EXTRA_CA_CERTS never replaces
 * them), so this grants no trust beyond that one CA - which is itself limited to private addresses.
 *
 * Returns nothing when `volume` is empty (BackOS served over plain HTTP or a public CA).
 */
export function caTrustSettings(volume: string | undefined): { dockerArgs: string[]; env: Record<string, string> } {
    const name = (volume ?? '').trim();
    if (!name) return { dockerArgs: [], env: {} };
    return {
        dockerArgs: ['-v', `${name}:${CA_MOUNT_DIR}:ro`],
        env: { NODE_EXTRA_CA_CERTS: `${CA_MOUNT_DIR}/ca.crt` },
    };
}
