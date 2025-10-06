// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// https://astro.build/config
export default defineConfig({
	integrations: [
		starlight({
			title:'卂ㄒ尺4乂',
			defaultLocale: 'es',
			locales: {
				es: { label: 'Español' },
				en: { label: 'English', lang: 'en' },
			},
			customCss: ['./src/fonts/font-face.css'],
			social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/blackhareigneo' }],
			sidebar: [
				{
					label: 'HTB',
					autogenerate: { directory: 'guides' },
				},
				{
					label: 'VullHub',
					autogenerate: { directory: 'reference' },
				},
			],
		}),
	],
	vite: {
		resolve: {
			alias: {
				// Redirige el componente original a tu versión personalizada
				'@astrojs/starlight/components/SiteTitle.astro': '/src/components/starlight/SiteTitle.astro',
			},
		},
	},
});
