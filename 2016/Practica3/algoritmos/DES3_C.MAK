CFLAGS   = /c /AL /G3 /DMSDOS               # controls compiler options
LFLAGS   = /ST:16000 /NOI /NOE              # controls linker options

OBJS = des3_c.obj crypt.obj tempfile.obj nextfile.obj getopt.obj crypth.obj hex.obj commode.obj

all : des3_c.exe

des3_c.exe : $(OBJS)
    link $(LFLAGS) @<<des3_c.lrf
$(OBJS: =+^
)
des3_c.exe
des3_c.map;
<<KEEP

crypt.obj: crypt.c crypt.h getopt.h nextfile.h tempfile.h
     CL $(CFLAGS) crypt.c

des3_c.obj : des3_c.c crypt.h hex.h des.h
     CL $(CFLAGS) des3_c.c

hex.obj: hex.c hex.h
     CL $(CFLAGS) hex.c

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


