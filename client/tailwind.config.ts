import type { Config } from 'tailwindcss'
import defaultTheme from 'tailwindcss/defaultTheme'

export default <Partial<Config>> {
  content: [],
  theme: {
    extend: {
      colors: {
        twitch: {
          50: '#f6f2ff',
          100: '#eee8ff',
          200: '#dfd4ff',
          300: '#cab1ff',
          400: '#b085ff',
          500: '#9146ff',
          600: '#8d30f7',
          700: '#7f1ee3',
          800: '#6a18bf',
          900: '#57169c',
          950: '#370b6a',
        },
        youtube: {
          50: '#fff0f0',
          100: '#ffdddd',
          200: '#ffc0c0',
          300: '#ff9494',
          400: '#ff5757',
          500: '#ff2323',
          600: '#ff0000',
          700: '#d70000',
          800: '#b10303',
          900: '#920a0a',
          950: '#500000',
        },
        discord: {
          50: '#eef3ff',
          100: '#e0e9ff',
          200: '#c6d6ff',
          300: '#a4b9fd',
          400: '#8093f9',
          500: '#5865f2',
          600: '#4445e7',
          700: '#3836cc',
          800: '#2f2fa4',
          900: '#2d2f82',
          950: '#1a1a4c',
        },
        twitter: {
          50: '#f0f8ff',
          100: '#e0effe',
          200: '#bae0fd',
          300: '#7ec7fb',
          400: '#39abf7',
          500: '#1d9bf0',
          600: '#0372c6',
          700: '#045ba0',
          800: '#084e84',
          900: '#0d416d',
          950: '#082949',
        },
        instagram: {
          50: '#fff1f2',
          100: '#ffdfe1',
          200: '#ffc5c9',
          300: '#ff9da5',
          500: '#ff3040',
          600: '#ed1526',
          700: '#c80d1b',
          800: '#a50f1b',
          900: '#88141d',
          950: '#4b0409',
        },
        kofi: {
          50: '#fff1f1',
          100: '#ffe2e1',
          200: '#ffc8c7',
          300: '#ffa2a0',
          400: '#ff5e5b',
          500: '#f83e3b',
          600: '#e5211d',
          700: '#c11714',
          800: '#a01714',
          900: '#841a18',
          950: '#480807',
        },
        patreon: {
          50: '#fff7ec',
          100: '#ffedd3',
          200: '#ffd8a5',
          300: '#ffbb6d',
          400: '#ff9232',
          500: '#ff730a',
          600: '#ff5900',
          700: '#cc3e02',
          800: '#a1310b',
          900: '#822b0c',
          950: '#461204',
        },
        paypal: {
          50: '#ecfbff',
          100: '#d4f4ff',
          200: '#b2eeff',
          300: '#7de7ff',
          400: '#40d5ff',
          500: '#14b7ff',
          600: '#0098ff',
          700: '#0080ff',
          800: '#0070e0',
          900: '#0857a0',
          950: '#0a3561',
        },
        spotify: {
          50: '#f0fdf4',
          100: '#dbfde7',
          200: '#b9f9ce',
          300: '#82f3aa',
          400: '#45e37d',
          500: '#1ed760',
          600: '#11a847',
          700: '#11843b',
          800: '#136832',
          900: '#12552c',
          950: '#042f16',
        },
        streamelements: {
          50: '#f0f1ff',
          100: '#e4e4ff',
          200: '#cdcfff',
          300: '#a6a6ff',
          400: '#7a73ff',
          500: '#503bff',
          600: '#3a14ff',
          700: '#2700ff',
          800: '#2201d6',
          900: '#1d03af',
          950: '#0d0077',
        },
        streamlabs: {
          50: '#eafff7',
          100: '#cdfeea',
          200: '#a0fada',
          300: '#80f5d2',
          400: '#25e2af',
          500: '#00c99a',
          600: '#00a47e',
          700: '#008369',
          800: '#006854',
          900: '#005546',
          950: '#003029',
        },
        throne: {
          50: '#ebf2ff',
          100: '#dbe7ff',
          200: '#bed1ff',
          300: '#96b2ff',
          400: '#6d86ff',
          500: '#4b5dff',
          600: '#2b2fff',
          700: '#2e2ee5',
          800: '#1c1eb7',
          900: '#20248f',
          950: '#131453',
        },
      }
    }
  },
  plugins: []
}