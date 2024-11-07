1. [Temporary Mounts](#temporary-mounts)
2. [Persistent Mounts](#persistent-mounts)

## Temporary Mounts
`xmount --in $IMAGE_TYPE $PATH_TO_IMAGE $PATH_TO_MNT`
--> will temporary mount (read only) an image in the defined path. It is possible to define the output image format.

## Persistent Mounts
To make a persistent mount of a disk image that survives reboots, you can use standard Linux mounting tools such as mount or fstab, which handle persistent mounts without needing xmount. Here’s a step-by-step guide on how to set up a persistent mount using either a raw image file or a specific partition within the image.
1. Identify the Type of Image File

First, verify the format of the image file to determine the appropriate mount options. For example:

    Raw disk images (.dd or .img) with no partitions can be mounted directly.
    Disk images with partitions will need to identify the specific partition.

2. Mount a Raw Disk Image

If the image file is a simple raw image (e.g., combined_image.dd) without any partitions, you can set it up as a persistent mount in /etc/fstab as follows.

    Mounting Steps:
        Create a mount point (directory) for the image:

sudo mkdir -p /mnt/your_mount_point

Add the following line to /etc/fstab:

/path/to/combined_image.dd /mnt/your_mount_point auto loop 0 0

    Replace /path/to/combined_image.dd with the full path to your image file.
    Replace /mnt/your_mount_point with the path to the directory you created for mounting.

Use the mount -a command to apply the changes without rebooting:

        sudo mount -a

This configuration in /etc/fstab will automatically mount the image to the specified directory at boot.
3. Mount a Disk Image with Partitions

For images with partitions, such as .dd files that represent an entire disk, you will need to specify the exact partition you want to mount.

    Steps to Identify and Mount Specific Partitions:

        Use fdisk or parted to list partitions within the image:

sudo fdisk -l /path/to/combined_image.dd

This command will show details about each partition, including the offset for each partition.

Use losetup to associate a loop device with the partition:

sudo losetup -Pf --show /path/to/combined_image.dd

This will map the image file to loop devices, with each partition available as /dev/loopXpY (e.g., /dev/loop0p1 for the first partition).

Add the specific partition to /etc/fstab:

/dev/loop0p1 /mnt/your_mount_point auto defaults 0 0

Run mount -a to immediately apply the new /etc/fstab entry:

        sudo mount -a

Note: This setup assumes losetup will consistently assign the same loop device on each boot. If it doesn’t, you may need to use a systemd service file or script to set up the loop devices consistently at boot.
4. Using systemd to Mount Dynamically with Scripts

If using /etc/fstab does not work due to variable device naming on boot, you can create a systemd service to handle the mount.

    Example systemd Service:

        Create a script to set up the mount:

sudo nano /usr/local/bin/mount_image.sh

    Add the following content to mount the image and make it executable:

#!/bin/bash
losetup -Pf /path/to/combined_image.dd
mount /dev/loop0p1 /mnt/your_mount_point

Make it executable:

    sudo chmod +x /usr/local/bin/mount_image.sh

Create a systemd service file:

sudo nano /etc/systemd/system/mount_image.service

    Add the following content:

    [Unit]
    Description=Mount Disk Image at Boot
    After=local-fs.target

    [Service]
    ExecStart=/usr/local/bin/mount_image.sh
    RemainAfterExit=yes

    [Install]
    WantedBy=multi-user.target

Enable and start the service:

        sudo systemctl enable mount_image.service
        sudo systemctl start mount_image.service

This setup will mount the image at boot and can be managed like any other service.

By following one of these methods, you can set up a disk image to persistently mount on boot. Each method offers flexibility depending on the image type and your setup requirements.