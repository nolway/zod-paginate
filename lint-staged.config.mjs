/**
 * @type {import('lint-staged').Configuration}
 */
export default {
  '*.{ts,js}': ['npm run lint:fix', 'git add .'],
};
