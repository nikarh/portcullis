// Docs link to each other site-absolute and without the base (`/policy/egress/`), since the same pages are built
// under a different base for every version. This Sätteri plugin adds the base to such links in Markdown and MDX.
import { defineMdastPlugin } from 'satteri';

/** @param {string} base */
export default function baseLinks(base) {
	const prefix = base.replace(/\/$/, '');
	/** @param {string} url */
	const rebase = (url) =>
		prefix && url.startsWith('/') && !url.startsWith('//') && !url.startsWith(`${prefix}/`) ? prefix + url : url;
	return defineMdastPlugin({
		name: 'portcullis-base-links',
		link(node, ctx) {
			const url = rebase(node.url);
			if (url !== node.url) ctx.setProperty(node, 'url', url);
		},
		definition(node, ctx) {
			const url = rebase(node.url);
			if (url !== node.url) ctx.setProperty(node, 'url', url);
		},
	});
}
