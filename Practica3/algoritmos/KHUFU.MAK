CFLAGS   = /c /AL /G3 /DMSDOS               # controls compiler options
LFLAGS   = /ST:16000 /NOI /NOE              # controls linker options

OBJS = khufu.obj crypt.obj nhash.obj rnd.obj tempfile.obj nextfile.obj getopt.obj crypth.obj commode.obj

all : khufu.exe

khufu.exe : $(OBJS)
    link $(LFLAGS) @<<khufu.lrf
$(OBJS: =+^
)
khufu.exe
khufu.map;
<<KEEP

crypt.obj: crypt.c crypt.h getopt.h nextfile.h tempfile.h
     CL $(CFLAGS) crypt.c

khufu.obj : khufu.c crypt.h rnd.h
     CL $(CFLAGS) khufu.c

rnd.obj : rnd.c
     CL $(CFLAGS) rnd.c

nhash.obj : nhash.c nhash.h
     CL $(CFLAGS) nhash.c

tempfile.obj : tempfile.c tempfile.h
     CL $(CFLAGS) tempfile.c

nextfile.obj : nextfile.c nextfile.h
     CL $(CFLAGS) nextfile.c

getopt.obj : getopt.c getopt.h
     CL $(CFLAGS) getopt.c

crypth.obj : crypth.c
     CL $(CFLAGS) crypth.c

commode.obj:

clean :
    -del *.obj
    -del *.map
    -del *.lrf


