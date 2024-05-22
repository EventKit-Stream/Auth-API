// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
  devtools: { enabled: false },
  ui: {
    icons: ['mdi', 'simple-icons', 'mingcute', 'heroicons'],
  },
  modules: [
    "@nuxt/ui",
    '@nuxtjs/seo',
    'nuxt-icon',
    'nuxt-og-image',
  ],

  pages: true,
  components: true,
  ssr:true,
  // target: 'static',
  // render: {
  //   resourceHints: false,
  // },
  // hooks: {
  //   'generate:page': page => {
  //     const doc = cheerio.load(page.html);
  //     doc(`body script`).remove();
  //     page.html = doc.html();
  //   },
  // },
  site: {
    indexable: false, //NOTE: set to true for the main service
    url: 'https://id.eventkit.stream',
    name: 'Event Kit',
    description: 'Event Kit is a platform dedicated to .....',
    defaultLocale: 'en', // not needed if you have @nuxtjs/i18n installed
    trailingSlash: false,
  },
  seo: {
    redirectToCanonicalSiteUrl: true
  },
})
