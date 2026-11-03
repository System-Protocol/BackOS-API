import * as path from 'path';

const REPO_ROOT = path.resolve(__dirname, '..', '..');

/**
 * The `-f` arguments for `docker compose`, shared by global setup and teardown so that both
 * address exactly the same set of services.
 *
 * `E2E_COMPOSE_OVERRIDE` (a path relative to the repository root, or absolute) adds one more
 * compose file on top of deploy/docker-compose.test.yml. The CI uses it to let generated
 * backends - which run in their own container - reach the test Postgres
 * (see deploy/docker-compose.test.ci.yml). Left unset, nothing changes.
 */
export function composeFileArgs(): string {
    const files = [path.join(REPO_ROOT, 'deploy', 'docker-compose.test.yml')];
    const override = process.env.E2E_COMPOSE_OVERRIDE;
    if (override) files.push(path.resolve(REPO_ROOT, override));

    return files.map((file) => `-f "${file}"`).join(' ');
}
