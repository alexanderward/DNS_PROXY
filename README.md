
## Dependencies

```
Python 2.7.x
pip install -r requirements.txt
```

## Arguments
```
-H = Host IP; Default is 127.0.0.1
-p = Host port; Default is 53
-s = DNS server to forward requests to; Required.
-C = disable caching; Default is set to false
-l = Logging level (10: debug, 20: info/default, 30: warning); default is 20
```

### Run
```
python run.py -s <dns server>
 
example: python run.py -s 8.8.8.8
```

### Hooks
```
1. Create new hooks in hooks.py.
    - You must implement the BaseHook class.
    - Hooks are auto-imported, no need to edit any other files.
    
2. Hook Return:
    - The first hook to return data will resolve the request
    - A hook must return DNSResponse[]
        - Empty array returned will continue to the next hook
        - Non-empty will resolve
        - If all are empty, it will resolve the request naturally
```


### Network View

```
    Client -> Script (Hooks hit) -> Client
    
    Client -> Script (No Hooks hit) -> Forward to DNS -> Script -> Client
```