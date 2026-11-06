// Checks every internal link and anchor of the built site in dist/, and fails listing the broken ones. Run by
// `npm run build`, with the same DOCS_VERSION, so that links are checked under the base they will be served at.
import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import { join, relative, dirname, posix } from 'node:path';

const dist = new URL('../dist/', import.meta.url).pathname;
const base = process.env.DOCS_VERSION ? `/${process.env.DOCS_VERSION}/` : '/';
// What lives next to this build on GitHub Pages, not in it: other versions and versions.json.
const beside = /^\/(?:main\/|v\d+\.\d+\.\d+\/|versions\.json$)/;

const pages = new Map();
const walk = (dir) => {
	for (const name of readdirSync(dir)) {
		const path = join(dir, name);
		if (statSync(path).isDirectory()) walk(path);
		else if (name.endsWith('.html')) pages.set(path, readFileSync(path, 'utf8'));
	}
};
walk(dist);

const ids = new Map();
const idsOf = (file) => {
	if (!ids.has(file)) {
		const html = pages.get(file) ?? readFileSync(file, 'utf8');
		ids.set(file, new Set([...html.matchAll(/\sid="([^"]+)"/g)].map((match) => match[1])));
	}
	return ids.get(file);
};

/** The file a site path is served from, or undefined. */
const fileFor = (path) => {
	const candidates = path.endsWith('/') ? [join(dist, path, 'index.html')] : [join(dist, path), join(dist, path, 'index.html')];
	return candidates.find((file) => existsSync(file) && statSync(file).isFile());
};

const broken = [];
for (const [file, html] of pages) {
	const pagePath = '/' + relative(dist, dirname(file)).split('\\').join('/') + '/';
	for (const [, attribute, raw] of html.matchAll(/\s(href|src)="([^"]*)"/g)) {
		const url = raw.replaceAll('&amp;', '&');
		if (/^(?:[a-z][a-z0-9+.-]*:|\/\/)/i.test(url) || url === '') continue;
		const [pathPart, hash] = url.split('#');
		let path;
		if (pathPart === '') path = pagePath;
		else if (pathPart.startsWith('/')) {
			if (!pathPart.startsWith(base)) {
				if (beside.test(pathPart)) continue;
				broken.push(`${relative(dist, file)}: ${attribute}="${url}" is outside the base ${base}`);
				continue;
			}
			path = '/' + pathPart.slice(base.length);
		} else path = posix.join(pagePath, pathPart);
		path = decodeURIComponent(path.split('?')[0]);
		const target = fileFor(path);
		if (!target) {
			broken.push(`${relative(dist, file)}: ${attribute}="${url}" has no page`);
		} else if (hash && target.endsWith('.html') && !idsOf(target).has(decodeURIComponent(hash))) {
			broken.push(`${relative(dist, file)}: ${attribute}="${url}" has no anchor #${hash}`);
		}
	}
}

if (broken.length) {
	console.error(`${broken.length} broken links:\n${[...new Set(broken)].join('\n')}`);
	process.exit(1);
}
console.log(`Checked the links of ${pages.size} pages.`);
