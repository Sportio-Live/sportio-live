// Tailwind build config for the two static pages in public/. The compiled
// output (public/tailwind.css) is committed so the app runs without a build
// step - rerun `npm run build:css` after changing classes in either page
// (CI checks that the committed file is up to date).
module.exports = {
  content: ['./public/**/*.html'],
  theme: { extend: {} },
  plugins: []
};
