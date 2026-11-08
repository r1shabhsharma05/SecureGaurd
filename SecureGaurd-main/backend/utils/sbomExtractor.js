/**
 * Multi-Ecosystem Software Bill of Materials (SBOM) Extractor
 * 
 * Supports static dependency parsing for:
 * 1. JavaScript / TypeScript (package.json, package-lock.json, yarn.lock, pnpm-lock.yaml)
 * 2. Python (requirements.txt, pyproject.toml, Pipfile, poetry.lock)
 * 3. Java (pom.xml, build.gradle, build.gradle.kts)
 * 4. Go (go.mod, go.sum)
 * 5. Rust (Cargo.toml, Cargo.lock)
 * 6. PHP (composer.json, composer.lock)
 * 7. Ruby (Gemfile, Gemfile.lock)
 * 
 * Generates standardized Package URLs (PURLs) and direct/transitive relationships.
 */

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

/**
 * Generate standard Package URL (PURL) according to PURL specification.
 */
function generatePurl(ecosystem, name, version) {
  if (!name || typeof name !== 'string') return null;
  const cleanVersion = version ? encodeURIComponent(version.trim().replace(/^v/i, '')) : 'unknown';
  const cleanName = name.trim();

  switch (ecosystem.toLowerCase()) {
    case 'npm':
    case 'javascript':
    case 'typescript': {
      if (cleanName.startsWith('@')) {
        const parts = cleanName.split('/');
        const scope = encodeURIComponent(parts[0]);
        const pkg = encodeURIComponent(parts.slice(1).join('/'));
        return `pkg:npm/${scope}/${pkg}@${cleanVersion}`;
      }
      return `pkg:npm/${encodeURIComponent(cleanName)}@${cleanVersion}`;
    }
    case 'pypi':
    case 'python': {
      const normalizedPyName = cleanName.toLowerCase().replace(/[-_.]+/g, '-');
      return `pkg:pypi/${encodeURIComponent(normalizedPyName)}@${cleanVersion}`;
    }
    case 'maven':
    case 'java': {
      if (cleanName.includes(':')) {
        const [group, artifact] = cleanName.split(':');
        return `pkg:maven/${encodeURIComponent(group)}/${encodeURIComponent(artifact)}@${cleanVersion}`;
      }
      return `pkg:maven/${encodeURIComponent(cleanName)}@${cleanVersion}`;
    }
    case 'golang':
    case 'go': {
      return `pkg:golang/${cleanName.split('/').map(encodeURIComponent).join('/')}@${cleanVersion}`;
    }
    case 'cargo':
    case 'rust': {
      return `pkg:cargo/${encodeURIComponent(cleanName)}@${cleanVersion}`;
    }
    case 'composer':
    case 'php': {
      if (cleanName.includes('/')) {
        const [vendor, pkg] = cleanName.split('/');
        return `pkg:composer/${encodeURIComponent(vendor)}/${encodeURIComponent(pkg)}@${cleanVersion}`;
      }
      return `pkg:composer/${encodeURIComponent(cleanName)}@${cleanVersion}`;
    }
    case 'rubygems':
    case 'ruby': {
      return `pkg:rubygems/${encodeURIComponent(cleanName)}@${cleanVersion}`;
    }
    default:
      return `pkg:generic/${encodeURIComponent(cleanName)}@${cleanVersion}`;
  }
}

/**
 * 1. JavaScript / TypeScript Extractor
 */
function extractNpmComponents(filePath, relPath, content) {
  const components = [];
  const fileName = path.basename(filePath);

  if (fileName.includes('package-lock.json')) {
    try {
      const lock = JSON.parse(content);
      const packages = lock.packages || lock.dependencies || {};

      for (const [pkgPath, pkgInfo] of Object.entries(packages)) {
        if (!pkgPath || pkgPath === '') continue;
        const name = pkgInfo.name || pkgPath.replace(/^node_modules\//, '').replace(/^.*node_modules\//, '');
        if (!name) continue;

        const version = pkgInfo.version || 'unknown';
        const isDirect = !pkgPath.includes('node_modules/') || pkgPath.split('node_modules/').length === 2;

        components.push({
          name,
          version,
          rawVersion: version,
          ecosystem: 'npm',
          packageManager: 'npm',
          dependencyType: isDirect ? 'direct' : 'transitive',
          manifestSource: relPath,
          purl: generatePurl('npm', name, version),
          license: pkgInfo.license || 'NOASSERTION',
          integrity: pkgInfo.integrity || null,
          dependencies: Object.keys(pkgInfo.dependencies || {})
        });
      }
    } catch (e) {}
  } else if (fileName.includes('package.json')) {
    try {
      const pkg = JSON.parse(content);
      const directDeps = Object.entries(pkg.dependencies || {});
      const devDeps = Object.entries(pkg.devDependencies || {});
      const peerDeps = Object.entries(pkg.peerDependencies || {});

      const processDep = (name, version, type) => {
        const cleanVer = version ? version.replace(/[\^~>=<]/g, '').trim() : 'unknown';
        components.push({
          name,
          version: cleanVer,
          rawVersion: version,
          ecosystem: 'npm',
          packageManager: 'npm',
          dependencyType: 'direct',
          manifestSource: relPath,
          purl: generatePurl('npm', name, cleanVer),
          license: pkg.license || 'NOASSERTION',
          dependencies: []
        });
      };

      directDeps.forEach(([n, v]) => processDep(n, v, 'direct'));
      devDeps.forEach(([n, v]) => processDep(n, v, 'direct'));
      peerDeps.forEach(([n, v]) => processDep(n, v, 'direct'));
    } catch (e) {}
  } else if (fileName === 'yarn.lock') {
    try {
      const lines = content.split('\n');
      let currentPkg = null;

      for (const line of lines) {
        const trimmed = line.trim();
        if (line.length > 0 && !line.startsWith(' ') && !line.startsWith('#')) {
          const match = trimmed.match(/^"?(@?[^@\n]+)@/);
          if (match) {
            currentPkg = { name: match[1], version: 'unknown', dependencies: [] };
          }
        } else if (currentPkg && trimmed.startsWith('version')) {
          const vMatch = trimmed.match(/version\s+"?([^"\n]+)"?/);
          if (vMatch) {
            currentPkg.version = vMatch[1];
            components.push({
              name: currentPkg.name,
              version: currentPkg.version,
              rawVersion: currentPkg.version,
              ecosystem: 'npm',
              packageManager: 'yarn',
              dependencyType: 'transitive',
              manifestSource: relPath,
              purl: generatePurl('npm', currentPkg.name, currentPkg.version),
              license: 'NOASSERTION',
              dependencies: []
            });
            currentPkg = null;
          }
        }
      }
    } catch (e) {}
  } else if (fileName === 'pnpm-lock.yaml') {
    try {
      const doc = yaml.load(content, { schema: yaml.DEFAULT_SAFE_SCHEMA });
      if (doc && doc.packages) {
        for (const pkgKey of Object.keys(doc.packages)) {
          // Key format e.g. /express@4.18.2 or /@types/node@18.0.0
          const cleanKey = pkgKey.replace(/^\//, '');
          const lastAt = cleanKey.lastIndexOf('@');
          if (lastAt > 0) {
            const name = cleanKey.substring(0, lastAt);
            const version = cleanKey.substring(lastAt + 1).split('(')[0];
            components.push({
              name,
              version,
              rawVersion: version,
              ecosystem: 'npm',
              packageManager: 'pnpm',
              dependencyType: 'transitive',
              manifestSource: relPath,
              purl: generatePurl('npm', name, version),
              license: 'NOASSERTION',
              dependencies: []
            });
          }
        }
      }
    } catch (e) {}
  }

  return components;
}

/**
 * 2. Python Extractor (requirements.txt, pyproject.toml, Pipfile, poetry.lock)
 */
function extractPythonComponents(filePath, relPath, content) {
  const components = [];
  const fileName = path.basename(filePath);

  if (fileName === 'requirements.txt' || fileName.endsWith('.req') || fileName.includes('requirements')) {
    const lines = content.split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) continue;

      const match = trimmed.match(/^([a-zA-Z0-9_\-.]+)\s*(?:==|>=|<=|~=|!=)?\s*([a-zA-Z0-9_\-.]+)?/);
      if (match) {
        const name = match[1];
        const version = match[2] || 'unknown';
        components.push({
          name,
          version,
          rawVersion: match[2] ? `==${match[2]}` : 'any',
          ecosystem: 'pypi',
          packageManager: 'pip',
          dependencyType: 'direct',
          manifestSource: relPath,
          purl: generatePurl('pypi', name, version),
          license: 'NOASSERTION',
          dependencies: []
        });
      }
    }
  } else if (fileName === 'pyproject.toml' || fileName === 'Pipfile') {
    const lines = content.split('\n');
    let inDeps = false;

    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
        inDeps = /dependencies|packages/i.test(trimmed);
        continue;
      }
      if (inDeps && trimmed && !trimmed.startsWith('#')) {
        const match = trimmed.match(/^([a-zA-Z0-9_\-.]+)\s*=\s*["']?([^"'\n]+)["']?/);
        if (match && match[1] !== 'python') {
          const name = match[1];
          const ver = match[2].replace(/[\^~>=<"]/g, '').trim();
          components.push({
            name,
            version: ver || 'unknown',
            rawVersion: match[2],
            ecosystem: 'pypi',
            packageManager: 'poetry',
            dependencyType: 'direct',
            manifestSource: relPath,
            purl: generatePurl('pypi', name, ver || 'unknown'),
            license: 'NOASSERTION',
            dependencies: []
          });
        }
      }
    }
  } else if (fileName === 'poetry.lock') {
    const lines = content.split('\n');
    let currentPkg = null;

    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed === '[[package]]') {
        if (currentPkg && currentPkg.name) {
          components.push(currentPkg);
        }
        currentPkg = {
          name: '',
          version: 'unknown',
          ecosystem: 'pypi',
          packageManager: 'poetry',
          dependencyType: 'transitive',
          manifestSource: relPath,
          purl: null,
          license: 'NOASSERTION',
          dependencies: []
        };
      } else if (currentPkg) {
        const nameMatch = trimmed.match(/^name\s*=\s*"([^"]+)"/);
        if (nameMatch) currentPkg.name = nameMatch[1];

        const verMatch = trimmed.match(/^version\s*=\s*"([^"]+)"/);
        if (verMatch) {
          currentPkg.version = verMatch[1];
          currentPkg.rawVersion = verMatch[1];
          currentPkg.purl = generatePurl('pypi', currentPkg.name, currentPkg.version);
        }
      }
    }
    if (currentPkg && currentPkg.name) {
      components.push(currentPkg);
    }
  }

  return components;
}

/**
 * 3. Java Extractor (pom.xml, build.gradle, build.gradle.kts)
 */
function extractJavaComponents(filePath, relPath, content) {
  const components = [];
  const fileName = path.basename(filePath);

  if (fileName.includes('pom.xml')) {
    const depRegex = /<dependency>[\s\S]*?<groupId>([^<]+)<\/groupId>[\s\S]*?<artifactId>([^<]+)<\/artifactId>(?:[\s\S]*?<version>([^<]+)<\/version>)?[\s\S]*?<\/dependency>/gi;
    let match;
    while ((match = depRegex.exec(content)) !== null) {
      const group = match[1].trim();
      const artifact = match[2].trim();
      const version = match[3] ? match[3].trim().replace(/\${.*}/g, 'unknown') : 'unknown';
      const name = `${group}:${artifact}`;

      components.push({
        name,
        version,
        rawVersion: version,
        ecosystem: 'maven',
        packageManager: 'maven',
        dependencyType: 'direct',
        manifestSource: relPath,
        purl: generatePurl('maven', name, version),
        license: 'NOASSERTION',
        dependencies: []
      });
    }
  } else if (fileName.includes('build.gradle')) {
    const lines = content.split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith('//')) continue;

      const gradleMatch = trimmed.match(/(?:implementation|api|compile|runtimeOnly)\s*\(?['"]([^'":]+):([^'":]+):([^'":]+)['"]/);
      if (gradleMatch) {
        const group = gradleMatch[1];
        const artifact = gradleMatch[2];
        const version = gradleMatch[3];
        const name = `${group}:${artifact}`;

        components.push({
          name,
          version,
          rawVersion: version,
          ecosystem: 'maven',
          packageManager: 'gradle',
          dependencyType: 'direct',
          manifestSource: relPath,
          purl: generatePurl('maven', name, version),
          license: 'NOASSERTION',
          dependencies: []
        });
      }
    }
  }

  return components;
}

/**
 * 4. Go Extractor (go.mod, go.sum)
 */
function extractGoComponents(filePath, relPath, content) {
  const components = [];
  const fileName = path.basename(filePath);

  if (fileName.includes('go.mod')) {
    const lines = content.split('\n');
    let inRequire = false;

    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith('require (')) {
        inRequire = true;
        continue;
      }
      if (inRequire && trimmed === ')') {
        inRequire = false;
        continue;
      }

      if (inRequire || trimmed.startsWith('require ')) {
        const clean = trimmed.replace(/^require\s+/, '');
        const parts = clean.split(/\s+/);
        if (parts.length >= 2) {
          const name = parts[0];
          const version = parts[1].replace(/^v/, '');
          const isIndirect = trimmed.includes('// indirect');

          components.push({
            name,
            version,
            rawVersion: parts[1],
            ecosystem: 'golang',
            packageManager: 'go',
            dependencyType: isIndirect ? 'transitive' : 'direct',
            manifestSource: relPath,
            purl: generatePurl('golang', name, version),
            license: 'NOASSERTION',
            dependencies: []
          });
        }
      }
    }
  } else if (fileName.includes('go.sum')) {
    const lines = content.split('\n');
    const seenMap = new Set();

    for (const line of lines) {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 3) {
        const name = parts[0];
        const version = parts[1].replace(/\/go\.mod$/, '').replace(/^v/, '');
        const key = `${name}@${version}`;
        if (seenMap.has(key)) continue;
        seenMap.add(key);

        components.push({
          name,
          version,
          rawVersion: parts[1],
          ecosystem: 'golang',
          packageManager: 'go',
          dependencyType: 'transitive',
          manifestSource: relPath,
          purl: generatePurl('golang', name, version),
          integrity: parts[2] || null,
          license: 'NOASSERTION',
          dependencies: []
        });
      }
    }
  }

  return components;
}

/**
 * 5. Rust Extractor (Cargo.toml, Cargo.lock)
 */
function extractRustComponents(filePath, relPath, content) {
  const components = [];
  const fileName = path.basename(filePath);

  if (fileName.includes('Cargo.toml')) {
    const lines = content.split('\n');
    let inDeps = false;

    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
        inDeps = /dependencies/i.test(trimmed);
        continue;
      }
      if (inDeps && trimmed && !trimmed.startsWith('#')) {
        const match = trimmed.match(/^([a-zA-Z0-9_\-.]+)\s*=\s*(?:["']([^"'\n]+)["']|\{\s*version\s*=\s*["']([^"'\n]+)["'])/);
        if (match) {
          const name = match[1];
          const ver = match[2] || match[3] || 'unknown';
          components.push({
            name,
            version: ver.replace(/[\^~>=<]/g, ''),
            rawVersion: ver,
            ecosystem: 'cargo',
            packageManager: 'cargo',
            dependencyType: 'direct',
            manifestSource: relPath,
            purl: generatePurl('cargo', name, ver.replace(/[\^~>=<]/g, '')),
            license: 'NOASSERTION',
            dependencies: []
          });
        }
      }
    }
  } else if (fileName.includes('Cargo.lock')) {
    const lines = content.split('\n');
    let currentPkg = null;

    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed === '[[package]]') {
        if (currentPkg && currentPkg.name) {
          components.push(currentPkg);
        }
        currentPkg = {
          name: '',
          version: 'unknown',
          ecosystem: 'cargo',
          packageManager: 'cargo',
          dependencyType: 'transitive',
          manifestSource: relPath,
          purl: null,
          license: 'NOASSERTION',
          dependencies: []
        };
      } else if (currentPkg) {
        const nameMatch = trimmed.match(/^name\s*=\s*"([^"]+)"/);
        if (nameMatch) currentPkg.name = nameMatch[1];

        const verMatch = trimmed.match(/^version\s*=\s*"([^"]+)"/);
        if (verMatch) {
          currentPkg.version = verMatch[1];
          currentPkg.rawVersion = verMatch[1];
          currentPkg.purl = generatePurl('cargo', currentPkg.name, currentPkg.version);
        }
      }
    }
    if (currentPkg && currentPkg.name) {
      components.push(currentPkg);
    }
  }

  return components;
}

/**
 * 6. PHP Extractor (composer.json, composer.lock)
 */
function extractPhpComponents(filePath, relPath, content) {
  const components = [];
  const fileName = path.basename(filePath);

  if (fileName === 'composer.json') {
    try {
      const json = JSON.parse(content);
      const reqs = { ...(json.require || {}), ...(json['require-dev'] || {}) };

      for (const [name, version] of Object.entries(reqs)) {
        if (name === 'php' || name.startsWith('ext-')) continue;
        const cleanVer = version ? version.replace(/[\^~>=<]/g, '').trim() : 'unknown';
        components.push({
          name,
          version: cleanVer,
          rawVersion: version,
          ecosystem: 'composer',
          packageManager: 'composer',
          dependencyType: 'direct',
          manifestSource: relPath,
          purl: generatePurl('composer', name, cleanVer),
          license: json.license ? (Array.isArray(json.license) ? json.license.join(' OR ') : json.license) : 'NOASSERTION',
          dependencies: []
        });
      }
    } catch (e) {}
  } else if (fileName === 'composer.lock') {
    try {
      const lock = JSON.parse(content);
      const pkgs = [...(lock.packages || []), ...(lock['packages-dev'] || [])];

      for (const p of pkgs) {
        const name = p.name;
        const version = p.version ? p.version.replace(/^v/i, '') : 'unknown';
        components.push({
          name,
          version,
          rawVersion: p.version,
          ecosystem: 'composer',
          packageManager: 'composer',
          dependencyType: 'transitive',
          manifestSource: relPath,
          purl: generatePurl('composer', name, version),
          license: p.license ? (Array.isArray(p.license) ? p.license.join(' OR ') : p.license) : 'NOASSERTION',
          dependencies: Object.keys(p.require || {})
        });
      }
    } catch (e) {}
  }

  return components;
}

/**
 * 7. Ruby Extractor (Gemfile, Gemfile.lock)
 */
function extractRubyComponents(filePath, relPath, content) {
  const components = [];
  const fileName = path.basename(filePath);

  if (fileName === 'Gemfile') {
    const lines = content.split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith('#')) continue;

      const gemMatch = trimmed.match(/^gem\s+["']([^"']+)["'](?:\s*,\s*["']([^"']+)["'])?/);
      if (gemMatch) {
        const name = gemMatch[1];
        const ver = gemMatch[2] ? gemMatch[2].replace(/[\^~>=<]/g, '').trim() : 'unknown';
        components.push({
          name,
          version: ver,
          rawVersion: gemMatch[2] || 'any',
          ecosystem: 'rubygems',
          packageManager: 'bundler',
          dependencyType: 'direct',
          manifestSource: relPath,
          purl: generatePurl('rubygems', name, ver),
          license: 'NOASSERTION',
          dependencies: []
        });
      }
    }
  } else if (fileName === 'Gemfile.lock') {
    const lines = content.split('\n');
    let inSpecs = false;

    for (const line of lines) {
      if (line.startsWith('  specs:')) {
        inSpecs = true;
        continue;
      }
      if (inSpecs && line.length > 0 && !line.startsWith(' ')) {
        inSpecs = false;
        continue;
      }

      if (inSpecs && line.startsWith('    ') && !line.startsWith('      ')) {
        const match = line.trim().match(/^([a-zA-Z0-9_\-.]+)\s*\(([^)]+)\)/);
        if (match) {
          const name = match[1];
          const version = match[2];
          components.push({
            name,
            version,
            rawVersion: version,
            ecosystem: 'rubygems',
            packageManager: 'bundler',
            dependencyType: 'transitive',
            manifestSource: relPath,
            purl: generatePurl('rubygems', name, version),
            license: 'NOASSERTION',
            dependencies: []
          });
        }
      }
    }
  }

  return components;
}

/**
 * Universal Manifest Scanner
 */
function parseManifestFile(fullPath, relPath) {
  try {
    const content = fs.readFileSync(fullPath, 'utf8');
    const fileName = path.basename(fullPath);

    if (fileName.includes('package.json') || fileName.includes('package-lock.json') || fileName.includes('yarn.lock') || fileName.includes('pnpm-lock.yaml')) {
      return extractNpmComponents(fullPath, relPath, content);
    }
    if (fileName.includes('requirements') || fileName.includes('pyproject.toml') || fileName.includes('Pipfile') || fileName.includes('poetry.lock') || fileName.endsWith('.req')) {
      return extractPythonComponents(fullPath, relPath, content);
    }
    if (fileName.includes('pom.xml') || fileName.includes('build.gradle')) {
      return extractJavaComponents(fullPath, relPath, content);
    }
    if (fileName.includes('go.mod') || fileName.includes('go.sum')) {
      return extractGoComponents(fullPath, relPath, content);
    }
    if (fileName.includes('Cargo.toml') || fileName.includes('Cargo.lock')) {
      return extractRustComponents(fullPath, relPath, content);
    }
    if (fileName.includes('composer.json') || fileName.includes('composer.lock')) {
      return extractPhpComponents(fullPath, relPath, content);
    }
    if (fileName.includes('Gemfile')) {
      return extractRubyComponents(fullPath, relPath, content);
    }
  } catch (err) {
    // Return empty array safely on malformed file
  }
  return [];
}

/**
 * Traverses repository directory, extracts raw components, and deduplicates.
 *
 * Symlink containment (same rule as utils/securityScanner.js): entries are
 * lstat'ed and symlinks skipped, directories are realpath-resolved and
 * required to stay inside the real scan root, visited directory inodes are
 * tracked, and traversal depth is capped.
 */
const MAX_TRAVERSAL_DEPTH = 32;

function extractRepositorySbomComponents(projectPath) {
  const allComponents = [];
  let rootReal = projectPath;
  try {
    rootReal = fs.realpathSync(projectPath);
  } catch {
    // keep projectPath; traversal below still skips symlinks
  }
  const visitedDirs = new Set();

  function traverse(dir, depth = 0) {
    if (depth > MAX_TRAVERSAL_DEPTH) return;
    let list = [];
    try {
      list = fs.readdirSync(dir);
    } catch {
      return;
    }

    for (const item of list) {
      const fullPath = path.join(dir, item);
      const relPath = path.relative(projectPath, fullPath);

      if (
        item === 'node_modules' ||
        item === '.git' ||
        item === 'dist' ||
        item === 'build' ||
        item === '.next' ||
        item === 'prisma' ||
        item === 'vendor' ||
        item === 'target'
      ) {
        continue;
      }

      // lstat, not stat: a symlink must never be followed.
      let stat;
      try {
        stat = fs.lstatSync(fullPath);
      } catch {
        continue;
      }
      if (stat.isSymbolicLink()) continue;

      if (stat.isDirectory()) {
        let realPath;
        try {
          realPath = fs.realpathSync(fullPath);
        } catch {
          continue;
        }
        if (realPath !== rootReal && !realPath.startsWith(rootReal + path.sep)) continue;
        const inodeKey = `${stat.dev}:${stat.ino}`;
        if (visitedDirs.has(inodeKey)) continue;
        visitedDirs.add(inodeKey);
        traverse(fullPath, depth + 1);
      } else if (stat.isFile()) {
        const extracted = parseManifestFile(fullPath, relPath);
        if (extracted.length > 0) {
          allComponents.push(...extracted);
        }
      }
    }
  }

  if (fs.existsSync(projectPath)) {
    traverse(projectPath);
  }

  // Deduplication & Aggregation Strategy
  const componentMap = new Map();

  for (const item of allComponents) {
    const key = `${item.ecosystem}:${item.name}@${item.version}`;
    
    if (componentMap.has(key)) {
      const existing = componentMap.get(key);
      // Promote dependencyType to 'direct' if any manifest declares it as direct
      if (item.dependencyType === 'direct') {
        existing.dependencyType = 'direct';
      }
      if (!existing.manifestSources.includes(item.manifestSource)) {
        existing.manifestSources.push(item.manifestSource);
      }
      if (!existing.integrity && item.integrity) {
        existing.integrity = item.integrity;
      }
      if (existing.license === 'NOASSERTION' && item.license !== 'NOASSERTION') {
        existing.license = item.license;
      }
    } else {
      componentMap.set(key, {
        ...item,
        manifestSources: [item.manifestSource]
      });
    }
  }

  return Array.from(componentMap.values());
}

module.exports = {
  generatePurl,
  parseManifestFile,
  extractRepositorySbomComponents
};
