const {defineConfig}=require('@playwright/test');
module.exports=defineConfig({
  testDir:'./e2e',testMatch:'review-workspace.spec.js',workers:1,fullyParallel:false,
  timeout:30000,outputDir:'./.tmp-review-test-results',reporter:'list',
  use:{baseURL:'http://127.0.0.1:4317',viewport:{width:1440,height:1000},screenshot:'only-on-failure',trace:'retain-on-failure'},
  webServer:{command:'node test-support/review-fixture.js',url:'http://127.0.0.1:4317/health',reuseExistingServer:false,timeout:60000}
});
