// @ts-check
import { defineConfig, passthroughImageService } from 'astro/config';
import starlight from '@astrojs/starlight';
import { satteri } from '@astrojs/markdown-satteri';
import baseLinks from './src/plugins/base-links.mjs';

// Every version of the docs is built on its own, into a directory of the gh-pages branch named after it
// (see scripts/docs-deploy.sh): DOCS_VERSION is `main` or a release tag, and the base is /portcullis/<version>/.
// Without DOCS_VERSION (mise run docs) the site is served at the root as `dev`.
const version = process.env.DOCS_VERSION || 'dev';
const base = process.env.DOCS_VERSION ? `/portcullis/${version}` : '/';

export default defineConfig({
	site: 'https://nikarh.github.io',
	base,
	trailingSlash: 'always',
	image: { service: passthroughImageService() },
	vite: { define: { 'import.meta.env.DOCS_VERSION': JSON.stringify(version) } },
	markdown: { processor: satteri({ mdastPlugins: [baseLinks(base)] }) },
	integrations: [
		starlight({
			title: 'Portcullis',
			description:
				'Limits what Docker containers can connect to, from labels on containers and networks, with nftables.',
			favicon: '/favicon.svg',
			social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/nikarh/portcullis' }],
			editLink: { baseUrl: 'https://github.com/nikarh/portcullis/edit/main/site/' },
			lastUpdated: false,
			customCss: [
				'@fontsource-variable/inter/wght.css',
				'@fontsource-variable/jetbrains-mono/wght.css',
				'./src/styles/theme.css',
			],
			components: {
				SiteTitle: './src/components/SiteTitle.astro',
				Banner: './src/components/Banner.astro',
			},
			expressiveCode: {
				themes: ['github-dark-default', 'github-light-default'],
				styleOverrides: {
					borderRadius: '6px',
					codeFontSize: '0.8125rem',
					frames: { editorActiveTabIndicatorTopColor: 'transparent', shadowColor: 'transparent' },
				},
			},
			sidebar: [
				{ label: 'Getting started', items: [{ autogenerate: { directory: 'start' } }] },
				{ label: 'Guides', items: [{ autogenerate: { directory: 'guides' } }] },
				{ label: 'Policy labels', items: [{ autogenerate: { directory: 'policy' } }] },
				{ label: 'Reference', items: [{ autogenerate: { directory: 'reference' } }] },
				{ label: 'Examples', items: [{ autogenerate: { directory: 'examples' } }] },
				{ label: 'How it works', items: [{ autogenerate: { directory: 'internals' } }] },
				{ label: 'Limits and workarounds', items: [{ autogenerate: { directory: 'limits' } }] },
				{ label: 'Help', items: [{ autogenerate: { directory: 'help' } }] },
				{ label: 'Project', collapsed: true, items: [{ autogenerate: { directory: 'project' } }] },
			],
		}),
	],
});
