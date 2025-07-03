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

3. Mount hugepages

```
mkdir -p /mnt/huge
mount -t hugetlbfs -o pagesize=2M none /mnt/huge
```

4. Run application on MaaXBoard

``` 
./test_dpdk_app --vdev='net_enetfec'
```
