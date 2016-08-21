# ICTSC6 NAT Kernel Module


###  Require Enviroment
Ubuntu 14.04 LTS
```
Linux s7-1 4.4.0-31-generic #50~14.04.1-Ubuntu SMP Wed Jul 13 01:07:32 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux
```

### build

```
sudo make -C /usr/local/src/linux-4.4.0-31-generic M=`pwd`

```


### install

```
sudo insmod post.core
```

### remove
```
sudo rmmod post.core
```
