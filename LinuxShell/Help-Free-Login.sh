#!/bin/sh

STVPubKey="/home/administrator/STV-tmp/id_rsa.pub"
STVAuthorizedKey="/home/administrator/STV-tmp/authorized_keys"
RootAuthorizedKey="/root/.ssh/authorized_keys"

if test $RootauthorizedKey
then
    echo "root.1234" | sudo -S rm $RootAuthorizedKey
fi

if test $STVPubKey
then
    echo "root.1234" | sudo -S cat $STVPubKey >> $STVAuthorizedKey
    echo "root.1234" | sudo -S chmod 600 $STVAuthorizedKey
    echo "root.1234" | sudo -S cp $STVAuthorizedKey $RootAuthorizedKey
    echo "root.1234" | sudo -S rm $STVPubKey
    echo "root.1234" | sudo -S rm $STVAuthorizedKey
fi

exit 0
