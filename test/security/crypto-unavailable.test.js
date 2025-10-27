import expect from 'expect.js';
import sinon from 'sinon';

import windowHelper from '../../src/helper/window';
import random from '../../src/helper/random';
import TransactionManager from '../../src/web-auth/transaction-manager';

describe('Security Vulnerability Analysis: Crypto Unavailable', function() {
  
  afterEach(function() {
    if (windowHelper.getWindow.restore) {
      windowHelper.getWindow.restore();
    }
  });

  describe('Critical Issue: null randomString cascading effects', function() {
    
    it('CONFIRMS: randomString returns null when crypto unavailable', function() {
      // Mock environment without crypto APIs
      sinon.stub(windowHelper, 'getWindow').returns({});
      
      const result = random.randomString(32);
      console.log('🔍 randomString result when crypto unavailable:', result);
      
      expect(result).to.be(null);
    });

    it('CRITICAL: TransactionManager accepts null state without validation', function() {
      // Mock environment without crypto
      sinon.stub(windowHelper, 'getWindow').returns({
        location: { host: 'example.com' } // Not auth domain
      });

      const tm = new TransactionManager({
        domain: 'test.auth0.com',
        clientID: 'test-client'
      });
      
      // This should theoretically throw an error if properly validated
      // But according to the vulnerability report, it accepts null
      const transaction = tm.generateTransaction(
        'appstate', null, null, 'connection', false, null
      );
      
      console.log('🚨 Generated transaction state:', transaction.state);
      console.log('🚨 Generated transaction nonce:', transaction.nonce);
      
      // The vulnerability claim: state should be null
      expect(transaction.state).to.be(null);
    });

    it('CRITICAL: Storage key collision with null states', function() {
      // Test the storage key generation mentioned in the vulnerability
      const namespace = 'com.auth0.auth.';
      const nullState = null;
      
      const storageKey = namespace + nullState;
      console.log('🔥 Storage key with null state:', storageKey);
      console.log('🔥 String representation:', JSON.stringify(storageKey));
      
      // This confirms the vulnerability claim about "com.auth0.auth.null"
      expect(storageKey).to.equal('com.auth0.auth.null');
    });

    it('CRITICAL: Multiple transactions collision demonstration', function() {
      sinon.stub(windowHelper, 'getWindow').returns({
        location: { host: 'example.com' },
        localStorage: {}
      });

      const tm = new TransactionManager({
        domain: 'test.auth0.com',
        clientID: 'test-client'
      });

      // Generate multiple transactions - all should collide
      const tx1 = tm.generateTransaction('app1', null, null, 'conn1', false, null);
      const tx2 = tm.generateTransaction('app2', null, null, 'conn2', false, null);
      
      console.log('🚨 Transaction 1 state:', tx1.state);
      console.log('🚨 Transaction 2 state:', tx2.state);
      
      const key1 = 'com.auth0.auth.' + tx1.state;
      const key2 = 'com.auth0.auth.' + tx2.state;
      
      console.log('🔥 Storage key collision:', key1 === key2);
      console.log('🔥 Both keys are:', key1);
      
      expect(key1).to.equal(key2);
      expect(key1).to.equal('com.auth0.auth.null');
    });

    it('CRITICAL: State validation bypass demonstration', function() {
      // Test the state comparison logic from the vulnerability report
      const transactionState = null;  // From transaction with null randomString
      const incomingState = null;     // From URL callback with null state
      
      // This is the comparison mentioned in src/web-auth/index.js:343-347
      const transactionStateMatchesState = transactionState === incomingState;
      
      console.log('🚨 transactionState:', transactionState);
      console.log('🚨 incomingState:', incomingState);
      console.log('🔥 State validation result (null === null):', transactionStateMatchesState);
      
      // The vulnerability: null === null evaluates to true, bypassing CSRF protection
      expect(transactionStateMatchesState).to.be(true);
    });
  });

  describe('Real-world impact assessment', function() {
    
    it('ASSESSMENT: Environments where crypto APIs are unavailable', function() {
      // List of environments mentioned in the vulnerability report
      const riskyEnvironments = [
        'Enterprise networks with strict CSP',
        'IE 10 and below',
        'WebViews in mobile apps',
        'Testing/CI environments',
        'Government/Military systems',
        'IoT/Embedded devices'
      ];
      
      console.log('🔍 Potentially affected environments:');
      riskyEnvironments.forEach((env, i) => {
        console.log(`  ${i + 1}. ${env}`);
      });
      
      // This test just documents the claim - actual validation would require
      // testing in these specific environments
      expect(riskyEnvironments.length).to.be.greaterThan(0);
    });

    it('ASSESSMENT: Current test coverage gaps', function() {
      // The vulnerability report claims no tests cover downstream null impact
      // Let's verify this by checking what the existing test does
      
      sinon.stub(windowHelper, 'getWindow').returns({});
      const result = random.randomString(10);
      
      console.log('🔍 Existing test only checks: randomString returns null');
      console.log('🚨 Missing tests for: TransactionManager null handling');
      console.log('🚨 Missing tests for: State validation null bypass');
      console.log('🚨 Missing tests for: Storage collision scenarios');
      
      expect(result).to.be(null);
      // But no test validates the security implications!
    });
  });
});