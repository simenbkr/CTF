@rem
@rem OS/2 test driver for bzip
@rem
type words1
.\bzip -Q -1 < sample1.ref > sample1.rbz
.\bzip -Q -2 < sample2.ref > sample2.rbz
.\bzip -Q -dV < sample1.bz > sample1.tst
.\bzip -Q -dV < sample2.bz > sample2.tst
type words3sh