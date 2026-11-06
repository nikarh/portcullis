// The releases in CHANGELOG.md (written by git-cliff when a release is made, see cliff.toml), for the changelog page
// and the front page. Each version of the docs shows the changelog as it was in that version.
import source from '../../CHANGELOG.md?raw';

const REPOSITORY = 'https://github.com/nikarh/portcullis';

export interface Release {
	/** `0.2.1`, without the `v`. */
	version: string;
	/** `2026-11-06`. */
	date: string | undefined;
	/** The release on GitHub. */
	url: string;
	/** `Features`, `Fixes`, ... and their entries, as HTML. */
	groups: { title: string; items: string[] }[];
}

const escape = (text: string) =>
	text.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');

/** One entry as HTML: `code`, **bold** and pull request numbers; who made it is left to the GitHub release. */
function entry(markdown: string): string {
	return escape(markdown.replace(/ by @[\w-]+/g, ''))
		.replace(/`([^`]+)`/g, '<code>$1</code>')
		.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
		.replace(/(^|[\s(])#(\d+)\b/g, `$1<a href="${REPOSITORY}/pull/$2">#$2</a>`);
}

function parse(markdown: string): Release[] {
	const releases: Release[] = [];
	let group: Release['groups'][number] | undefined;
	for (const line of markdown.split('\n')) {
		const heading = line.match(/^## \[([^\]]+)\](?: - (\S+))?/);
		if (heading) {
			const [, version, date] = heading;
			releases.push({ version, date, url: `${REPOSITORY}/releases/tag/v${version}`, groups: [] });
			group = undefined;
			continue;
		}
		const release = releases.at(-1);
		if (!release) continue;
		const title = line.match(/^### (.+)/);
		if (title) {
			group = { title: title[1].trim(), items: [] };
			release.groups.push(group);
		} else if (group && line.startsWith('- ')) {
			group.items.push(entry(line.slice(2).trim()));
		} else if (group && /^\s+\S/.test(line) && group.items.length) {
			// A wrapped entry.
			group.items[group.items.length - 1] += ` ${entry(line.trim())}`;
		}
	}
	// Unreleased changes aren't in a version's docs; the link definitions at the end aren't releases.
	return releases.filter((release) => /^\d+\.\d+\.\d+/.test(release.version));
}

export const releases: Release[] = parse(source);
