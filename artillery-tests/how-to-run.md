## How to run the performance test.

In this tests we have 4 tests which are 
 1. Load test
 2. Stress test
 3. Spike test
 4. Athentication test

 The main aim of each of these tests is to test the performance of the StatusList Sever.

### Step 1:
Ensure you have artillery installed in your machine

```bash
# global
npm install -g artillery
```
### Step 3:
The next step is to generate multiple test tokens that we can use during the performance test

```bash
# go to the test directory
cd artillery
npm install

# run this
npm run generate-tokens
```
### Step 4:
Create an artillery account at artillery.io. After creating the account, copy the access key, it should look like this (`artillery run test.yml --record --key YOUR_ACCESS_KEY`) on the welcome screen.

### Step 5:
Run the test.
```bash
 artillery run your_test.yml --name "stress-test" --record --key YOUR_ACCESS_KEY
 ```

## Memory and CPU usage

Go to `localhost:9090` to access the prometheus dashbord. After that, search for the memory or cpu usage

**Memory usage**: 
```
process_resident_memory_bytes{job="rust_app"} / 1024 / 1024
```

**CPU usage**: 
```
rate(process_cpu_seconds_total[30s]) * 100
```

Click on graph to see the graph of each.