# README

## Usage

1. Enter docker container
``` 
make docker
```

2. Compile the DPDK application
```
make app
```
3. Run application on MaaXBoard

``` 
./test_dpdk_app --no-huge --vdev='net_enetfec'
```
