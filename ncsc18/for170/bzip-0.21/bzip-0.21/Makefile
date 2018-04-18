
SH = ADE:bin/sh
OBJS= bzip.o

all: build
	cat words0
	delete bunzip
	cat words1
	bzip -Q -1 < sample1.ref > sample1.rbz
	bzip -Q -2 < sample2.ref > sample2.rbz
	bzip -Q < sample1.bz > sample1.tst
	bzip -Q < sample2.bz > sample2.tst
	cat words2
	cmp sample1.bz sample1.rbz 
	cmp sample2.bz sample2.rbz
	cmp sample1.tst sample1.ref
	cmp sample2.tst sample2.ref
	cat words3

build: bzip
#    assign include: sc:unix/include
	sc link to bzip $(OBJS)
#	assign include: sc:include

bzip: $(OBJS)
	sc link to bzip with << $(OBJS) <

bzip.o: bzip.c

clean:
	rm -f bzip bunzip sample*.tst sample*.rbz

