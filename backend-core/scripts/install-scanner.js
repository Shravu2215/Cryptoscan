const { execSync } = require('child_process');
const path = require('path');
const fs = require('fs');

const scannerDir = path.resolve(__dirname, '../../scanner');
const venvDir = path.join(scannerDir, '.venv');

console.log('Checking scanner virtual environment at:', venvDir);

const isWin = process.platform === 'win32';
const pythonCmd = isWin ? 'python' : 'python3';
const pipCmd = isWin ? path.join(venvDir, 'Scripts', 'pip.exe') : path.join(venvDir, 'bin', 'pip');

try {
  if (!fs.existsSync(venvDir)) {
    console.log('Creating virtual environment...');
    execSync(`${pythonCmd} -m venv .venv`, { cwd: scannerDir, stdio: 'inherit' });
  } else {
    console.log('Virtual environment already exists.');
  }

  console.log('Installing/updating dependencies from requirements.txt...');
  execSync(`"${pipCmd}" install -r requirements.txt`, { cwd: scannerDir, stdio: 'inherit' });
  console.log('Scanner environment is fully configured!');
} catch (err) {
  console.error('Error configuring scanner virtual environment:', err.message);
  // Do not fail the build if python isn't installed in the environment (e.g. some Node-only containers)
  // as it will fall back to system python at runtime.
}
