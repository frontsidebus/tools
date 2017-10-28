#!/bin/bash

#LOG=/root/test.log
#so we have an extra fstab file to rollback to

backup_fstab () {
        BACKUP_DIR=/.armor/BACKUP
        FSTAB=/etc/fstab
        if [ -d $BACKUP_DIR ]; then
                cp -a $FSTAB $BACKUP_DIR
        else
                cp -a $FSTAB /root/.
        fi
}

#Set currently running tmp dirs with exec, THIS IS NOT PERSISENT

running_tmp () {
        TMPFS=(
    "tmpfs"
    "/tmp"
    "/var/tmp"
    )
        for FS in "${TMPFS[@]}"
                do
                mount -o remount,rw,exec $TMPFS
                done
}

#Make exec persistent for tmp filesystems

mod_fstab () {
        FSTAB=/etc/fstab
        sed -i '/.*tmp.*/s/noexec/exec/g' $FSTAB
        sed -i '/.*tmp.*/s/defaults/rw\,exec/g' $FSTAB
        mount -a
}

backup_fstab
running_tmp
mod_fstab