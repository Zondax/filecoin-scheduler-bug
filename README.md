filecoin-scheduler-bug

```
export FIL_PROOFS_USE_GPU_TREE_BUILDER=1
export FIL_PROOFS_USE_GPU_COLUMN_BUILDER=1
export RUST_LOG="bellperson=trace,client=trace,scheduler=debug"

cargo build
```


Works:
```
./target/debug/parallel_mimc -t 4 
```

Fails:
```
./target/debug/hang -t 4
```

----

## Monitoring

Launch monitor:
```
cargo run -- -a 127.0.0.1:5000 monitor -r 300
```

Abort active job:
```
curl -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "abort", "id":1, "params":[job_id1]}' 127.0.0.1:5000
```

Remove stalled:
```
curl -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "remove_stalled", "id":1, "params":[job_id1]}' 127.0.0.1:5000
```