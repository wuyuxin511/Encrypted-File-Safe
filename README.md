# SafeBox

## Requirements
Linux kernel 2.6 or higher

## Dependencies
> libudev-dev  
  libdevmapper-dev

## Compilation
> make build

## Usage

1. Create a file for virtual file system, et. 
    ```
    $dd if=/dev/zero of=/home/zone.fs bs=1M count=512
    ```
2. Creat a key, encrypted with password
    ```
    $./main -g
    ```
3. Setup device-mapper. Require superuser privileges.
    ```
    $./main -s safezone
    ```
4. Create the actual filesystem on /dev/mapper/safezone, et.
    ```
    $mke2fs /dev/mapper/safezone
    ```
5. Release device-mapper. Require superuser privileges.
    ```
    $./main -r safezone
    ```
6. Mount on the encrypted filesystem.
    ```
    $./main -m safezone
    ```
7. Remember to unmount.
    ```
    $./main -u safezone
    ```
8. You can also change the password without changing raw key.
    ```
    $./main -c <path_to_key>
    ```
