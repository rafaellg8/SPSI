CFLAGS   = /c /AL /G3 /DMSDOS               # controls compiler options
LFLAGS   = /ST:16000 /NOI /NOE              # controls linker options

OBJS = lucifr_c.obj crypt.obj nhash.obj tempfile.obj nextfile.obj getopt.obj crypth.obj hex.obj commode.obj

all : lucifr_c.exe

lucifr_c.exe : $(OBJS)
    link $(LFLAGS) @<<lucifr_c.lrf
$(OBJS: =+^
)
lucifr_c.exe
lucifr_c.map;
<<KEEP

crypt.obj: crypt.c crypt.h getopt.h nextfile.h tempfile.h
     CL $(CFLAGS) crypt.c

lucifr_c.obj : lucifr_c.c crypt.h hex.h lucifer.h nhash.h
     CL $(CFLAGS) lucifr_c.c

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


