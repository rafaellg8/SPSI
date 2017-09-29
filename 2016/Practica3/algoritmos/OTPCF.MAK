CFLAGS   = /c /AL /G3 /Oilt /DMSDOS /DSMALL_MEM /DNO_ASM 
LFLAGS   = /ST:16000 /NOI /NOE

OBJS = otpcf.obj zblzss.obj crypt.obj tempfile.obj nextfile.obj \
       getopt.obj crypth.obj commode.obj


all : otpcf.exe

otpcf.exe : $(OBJS)
    link $(LFLAGS) @<<otpcf.lrf
$(OBJS: =+^
)
otpcf.exe
otpcf.map;
<<KEEP

crypt.obj: crypt.c crypt.h getopt.h nextfile.h tempfile.h
     CL $(CFLAGS) crypt.c

otpcf.obj : otpcf.c crypt.h tempfile.h zblock.h
     CL $(CFLAGS) otpcf.c

zblzss.obj : zblzss.c zblock.h
     CL $(CFLAGS) zblzss.c

tempfile.obj : tempfile.c tempfile.h
     CL $(CFLAGS) tempfile.c

nextfile.obj : nextfile.c nextfile.h
     CL $(CFLAGS) nextfile.c

getopt.obj : getopt.c getopt.h
     CL $(CFLAGS) getopt.c

crypth.obj : crypth.c
     CL $(CFLAGS) crypth.c

commode.obj :

zbits.obj : zbits.c zip.h ztailor.h ziperr.h

zdeflate.obj : zdeflate.c zunzip.h usuals.h zip.h ztailor.h ziperr.h 

zfile_io.obj : zfile_io.c zunzip.h usuals.h 

zglobals.obj : zglobals.c zip.h ztailor.h ziperr.h zblock.h

zinflate.obj : zinflate.c zunzip.h usuals.h 

zip.obj : zip.c usuals.h ziperr.h 

zipup.obj : zipup.c zip.h ztailor.h ziperr.h 

ztrees.obj : ztrees.c zip.h ztailor.h ziperr.h 

zunzip.obj : zunzip.c zunzip.h usuals.h zblock.h 

clean :
    -del *.obj
    -del *.map
    -del *.lrf


