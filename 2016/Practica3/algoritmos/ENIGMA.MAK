CFLAGS   = /c /AL /G3 /DMSDOS               # controls compiler options
LFLAGS   = /ST:16000 /NOI /NOE              # controls linker options

OBJS = enigma.obj crypt.obj tempfile.obj nextfile.obj getopt.obj crypth.obj commode.obj

all : enigma.exe

enigma.exe : $(OBJS)
    link $(LFLAGS) @<<enigma.lrf
$(OBJS: =+^
)
enigma.exe
enigma.map;
<<KEEP

crypt.obj: crypt.c crypt.h getopt.h nextfile.h tempfile.h
     CL $(CFLAGS) crypt.c

enigma.obj : enigma.c crypt.h
     CL $(CFLAGS) enigma.c

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


