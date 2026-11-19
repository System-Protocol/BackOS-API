import { CA_MOUNT_DIR, caTrustSettings } from './ca-trust.util';

describe('caTrustSettings', () => {
    it('sans volume : aucun changement pour le conteneur', () => {
        for (const v of [undefined, '', '   ']) {
            expect(caTrustSettings(v)).toEqual({ dockerArgs: [], env: {} });
        }
    });

    it('avec un volume : montage en LECTURE SEULE et confiance ajoutée (pas remplacée)', () => {
        const { dockerArgs, env } = caTrustSettings(' backos-lan-tls-public ');
        expect(dockerArgs).toEqual(['-v', `backos-lan-tls-public:${CA_MOUNT_DIR}:ro`]);
        expect(env).toEqual({ NODE_EXTRA_CA_CERTS: `${CA_MOUNT_DIR}/ca.crt` });
        // L'option "ro" est indispensable : le conteneur ne doit pas pouvoir modifier le certificat de confiance.
        expect(dockerArgs[1].endsWith(':ro')).toBe(true);
        // NODE_EXTRA_CA_CERTS s'ajoute aux racines habituelles ; ce n'est pas NODE_TLS_REJECT_UNAUTHORIZED=0.
        expect(Object.keys(env)).not.toContain('NODE_TLS_REJECT_UNAUTHORIZED');
    });
});
