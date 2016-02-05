CFLAGS   = /c /AL /G3 /DMSDOS               # controls compiler options
LFLAGS   = /ST:16000 /NOI /NOE              # controls linker options

OBJS = des1_c.obj crypt.obj tempfile.obj nextfile.obj getopt.obj crypth.obj hex.obj commode.obj

all : des1_c.exe

des1_c.exe : $(OBJS)
    link $(LFLAGS) @<<des1_c.lrf
$(OBJS: =+^
)
des1_c.exe
des1_c.map;
<<KEEP

crypt.obj: crypt.c crypt.h getopt.h nextfile.h tempfile.h
     CL $(CFLAGS) crypt.c

des1_c.obj : des1_c.c crypt.h hex.h des.h
     CL $(CFLAGS) des1_c.c

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


