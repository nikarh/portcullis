// The versions of the docs published on GitHub Pages, from /versions.json.

const ROOT = '/';

export interface Versions {
	/** Every published version, newest first: `main`, then releases. */
	all: string[];
	/** The newest release, if there is one. */
	latest: string | undefined;
}

let cached: Promise<Versions | undefined> | undefined;

export function loadVersions(): Promise<Versions | undefined> {
	cached ??= fetch(`${ROOT}versions.json`)
		.then((response) => (response.ok ? response.json() : undefined))
		.then((all: unknown) => {
			if (!Array.isArray(all)) return undefined;
			const names = all.filter((name): name is string => typeof name === 'string');
			return { all: names, latest: names.find((name) => name.startsWith('v')) };
		})
		.catch(() => undefined);
	return cached;
}

/** The same page in another version, or that version's front page if it has no such page. */
export async function versionUrl(from: string, to: string): Promise<string> {
	const prefix = `${ROOT}${from}/`;
	const { pathname, hash } = window.location;
	const rest = pathname.startsWith(prefix) ? pathname.slice(prefix.length) : '';
	const target = `${ROOT}${to}/${rest}`;
	if (rest) {
		const found = await fetch(target, { method: 'HEAD' })
			.then((response) => response.ok)
			.catch(() => false);
		if (!found) return `${ROOT}${to}/`;
	}
	return target + hash;
}
