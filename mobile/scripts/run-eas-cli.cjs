const { spawnSync } = require('node:child_process');

const command = process.platform === 'win32' ? 'npx.cmd' : 'npx';
const nodeOptions = [process.env.NODE_OPTIONS, '--dns-result-order=ipv4first']
  .filter(Boolean)
  .join(' ');
const result = spawnSync(command, ['eas-cli', ...process.argv.slice(2)], {
  env: { ...process.env, NODE_OPTIONS: nodeOptions },
  shell: process.platform === 'win32',
  stdio: 'inherit',
});

if (result.error) {
  console.error(result.error.message);
  process.exitCode = 1;
} else {
  process.exitCode = result.status ?? 1;
}
