CFLAGS   = /c /AL /G3 /DMSDOS               # controls compiler options
LFLAGS   = /ST:16000 /NOI /NOE              # controls linker options

OBJS = idea.obj crypt.obj idea128c.obj nhash.obj tempfile.obj nextfile.obj getopt.obj crypth.obj hex.obj commode.obj

all : idea_c.exe

idea_c.exe : $(OBJS)
    link $(LFLAGS) @<<idea_c.lrf
$(OBJS: =+^
)
idea_c.exe
idea_c.map;
<<KEEP

crypt.obj: crypt.c crypt.h getopt.h nextfile.h tempfile.h
     CL $(CFLAGS) crypt.c

idea128c.obj : idea128c.c crypt.h hex.h idea.h nhash.h usuals.h
     CL $(CFLAGS) idea128c.c

idea.obj : idea.c idea.h usuals.h
     CL $(CFLAGS) idea.c

nhash.obj : nhash.c nhash.h
     CL $(CFLAGS) nhash.c

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


