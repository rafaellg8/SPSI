CFLAGS   = /c /AL /G3 /DMSDOS               # controls compiler options
LFLAGS   = /ST:16000 /NOI /NOE              # controls linker options

OBJS = tinyrsa.obj crypt.obj tempfile.obj nextfile.obj getopt.obj crypth.obj commode.obj

all : tinyrsa.exe

tinyrsa.exe : $(OBJS)
    link $(LFLAGS) @<<tinyrsa.lrf
$(OBJS: =+^
)
tinyrsa.exe
tinyrsa.map;
<<KEEP

crypt.obj: crypt.c crypt.h getopt.h nextfile.h tempfile.h
     CL $(CFLAGS) crypt.c

tinyrsa.obj : tinyrsa.c crypt.h
     CL $(CFLAGS) tinyrsa.c

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


