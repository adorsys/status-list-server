## How to run the performance test

In this test we have 4 test which are 
 1. Load test
 2. Stress test
 3. Spike test
 4. Athentication test

 The main aim of each of these test is to test the performance of the StatusList Sever.

### Step 1:
Esure you have artillery installed in your machine

```bash
# global
npm install -g artillery
```
### Step 3
The next step is to generate multiple test tokens that we can use during the performance test

```bash
# go to the test directory
cd artillery

#run this
node token-generator.js
```
### Step 4
Create an artillery accoung at artillery.io. After creating the account, copy the access key, it should look like this (`artillery run test.yml --record --key YOUR_ACCESS_KEY`) on the welcom screen.

### Step 5
Run the test.
```bash
 artillery run your_test.yml --name "stress-test" --record --key YOUR_ACCESS_KEY
 ```

