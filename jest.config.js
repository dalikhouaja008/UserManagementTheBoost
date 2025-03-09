module.exports = {
    moduleFileExtensions: ['js', 'json', 'ts'],
    rootDir: 'src',
    testRegex: '.*\\.spec\\.ts$',
    transform: {
      '^.+\\.(t|j)s$': 'ts-jest'
    },
    collectCoverageFrom: [
      '**/*.ts',
      '!**/*.module.ts',
      '!main.ts',
      '!**/node_modules/**'
    ],
    coverageDirectory: '../coverage',
    testEnvironment: 'node'
  };