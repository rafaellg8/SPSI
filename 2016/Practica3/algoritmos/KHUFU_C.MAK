CFLAGS   = /c /AL /G3 /DMSDOS               # controls compiler options
LFLAGS   = /ST:16000 /NOI /NOE              # controls linker options

OBJS = khufu_c.obj crypt.obj nhash.obj rnd.obj tempfile.obj nextfile.obj getopt.obj crypth.obj commode.obj

all : khufu_c.exe

khufu_c.exe : $(OBJS)
    link $(LFLAGS) @<<khufu_c.lrf
$(OBJS: =+^
)
khufu_c.exe
khufu_c.map;
<<KEEP

crypt.obj: crypt.c crypt.h getopt.h nextfile.h tempfile.h
     CL $(CFLAGS) crypt.c

khufu_c.obj : khufu_c.c crypt.h rnd.h
     CL $(CFLAGS) khufu_c.c

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


