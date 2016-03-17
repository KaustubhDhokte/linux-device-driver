# linux-device-driver
Stacked block device driver that caches certain number of write IOs and flushes them to disk when the number reaches to a threshold value given by the user.

Stacked block device driver (sdc_driver) is a linux kernel module.
Threshold value (THRESHOLD_IO_CNT) is provided by the user as a module parameter at the time of module load.
All the write IOs to disk are cached in the in-memory kernel data structure: kfifo.
Once the requests count reaches to user provided threshold value, all the requests are flushed to the disk using workqueues.
Workqueues implicitly carry out this task in a separate kernel thread and the module keeps on buffering the new incoming requests.

The driver exports memory and IO requests related information in procfs.

Module Usage:
1. Build the module
      #> make clean && make all
      
Sample OP:

      make[1]: Entering directory `/usr/src/linux-headers-3.13.0-32-generic'
      make[1]: Leaving directory `/usr/src/linux-headers-3.13.0-32-generic'
      make -C /lib/modules/3.13.0-32-generic/build M=/home/ubuntu/try/linux-device-driver modules
      make[1]: Entering directory `/usr/src/linux-headers-3.13.0-32-generic'
      CC [M]  /home/ubuntu/try/linux-device-driver/sdc_driver.o
      Building modules, stage 2.
      MODPOST 1 modules
      CC      /home/ubuntu/try/linux-device-driver/sdc_driver.mod.o
      LD [M]  /home/ubuntu/try/linux-device-driver/sdc_driver.ko
      make[1]: Leaving directory `/usr/src/linux-headers-3.13.0-32-generic'

2. Load the module

      #> insmod sdc_driver.ko THRESHOLD_IO_CNT=5
  
    This will create the device entry /dev/sdc0
    
3. See module logs

      #> dmesg


Procfs Usage with sample output:

1. Total memory currently used by the driver:
    
    #> cat /proc/sdc_memory_consumption

      root@ubuntu-VirtualBox:/home/ubuntu/try/linux-device-driver# cat /proc/sdc_memory_consumption
      Total memory taken by driver: 32776 Bytes
      root@ubuntu-VirtualBox:/home/ubuntu/try/linux-device-driver# 
      
2. Forcefully flush the in memory data to the disk:

    #> echo 1 > /proc/sdc_flush_io

      root@ubuntu-VirtualBox:/home/ubuntu/try/linux-device-driver# echo 1 > /proc/sdc_flush_io
      root@ubuntu-VirtualBox:/home/ubuntu/try/linux-device-driver# 

3. Number of batches of IOs are flushed to the disk by now:

    #> cat /proc/sdc_flushed_batches 
    
      root@ubuntu-VirtualBox:/home/ubuntu/try/linux-device-driver# cat /proc/sdc_flushed_batches 
      Batches of IO's fulshed: 1
      root@ubuntu-VirtualBox:/home/ubuntu/try/linux-device-driver#
    
4. Total amount of data that is in memory and need to flush to the disk:

    #> cat /proc/sdc_inmemory_data

      root@ubuntu-VirtualBox:/home/ubuntu/try/linux-device-driver# cat /proc/sdc_inmemory_data 
      Total in-memory data : 12336 Bytes
      root@ubuntu-VirtualBox:/home/ubuntu/try/linux-device-driver#
