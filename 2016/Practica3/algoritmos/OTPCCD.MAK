CFLAGS   = /c /AL /G3 /Oilt /DMSDOS /DSMALL_MEM /DNO_ASM 
LFLAGS   = /ST:16000 /NOI /NOE

OBJS = otpccd.obj zblzss.obj crypt.obj tempfile.obj nextfile.obj \
       getopt.obj crypth.obj cdromc.obj commode.obj

all : otpccd.exe

otpccd.exe : $(OBJS)
    link $(LFLAGS) @<<otpccd.lrf
$(OBJS: =+^
)
otpccd.exe
otpccd.map;
<<KEEP

crypt.obj: crypt.c crypt.h getopt.h nextfile.h tempfile.h
     CL $(CFLAGS) crypt.c

otpccd.obj : otpccd.c crypt.h tempfile.h zblock.h
     CL $(CFLAGS) otpccd.c

zblzss.obj : zblzss.c zblock.h
     CL $(CFLAGS) zblzss.c

cdromc.obj : cdromc.c cdromc.h zblock.h
     CL $(CFLAGS) cdromc.c

tempfile.obj : tempfile.c tempfile.h
     CL $(CFLAGS) tempfile.c

nextfile.obj : nextfile.c nextfile.h
     CL $(CFLAGS) nextfile.c

getopt.obj : getopt.c getopt.h
     CL $(CFLAGS) getopt.c

crypth.obj : crypth.c
     CL $(CFLAGS) crypth.c

commode.obj :

clean :
    -del *.obj
    -del *.map
    -del *.lrf


