#!/bin/bash -e
# $File: update.sh
# $Date: Fri Jul 25 12:16:36 2014 -0700
# $Author: jiakai <jia.kai66@gmail.com>

GPDIR=$1

if [ -z "$GPDIR" ]
then
    echo "usage: $0 <gperftools source directory>"
    exit -1
fi

GPDIR=$GPDIR/src

rm -rf *.h *.cpp

cp "$GPDIR"/base/{basictypes.h,logging.h,commandlineflags.h,sysinfo.h,\
dynamic_annotations.h,cycleclock.h,arm_instruction_set_select.h} .
cp "$GPDIR"/base/{logging.cc,sysinfo.cc} .
cp "$GPDIR"/profiledata.{h,cc} .
cp "$GPDIR/config.h" .

for i in *.cc
do
    mv $i ${i%.cc}.cpp
done

sed -e 's/<config.h>/"config.h"/g' *.cpp *.h -i
sed -e 's/"base\/\(.*\.h\)"/".\/\1"/g' *.cpp *.h -i

cat > fake.cpp <<FAKE
#include "dynamic_annotations.h"
int RunningOnValgrind() {
    return 0;
}
FAKE

