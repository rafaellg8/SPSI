CFLAGS   = /c /AL /G3 /DMSDOS               # controls compiler options
LFLAGS   = /ST:16000 /NOI /NOE              # controls linker options

OBJS = template.obj crypt.obj tempfile.obj nextfile.obj getopt.obj crypth.obj commode.obj

all : template.exe

template.exe : $(OBJS)
    link $(LFLAGS) @<<template.lrf
$(OBJS: =+^
)
template.exe
template.map;
<<KEEP

crypt.obj: crypt.c crypt.h getopt.h nextfile.h tempfile.h
     CL $(CFLAGS) crypt.c

template.obj : template.c crypt.h
     CL $(CFLAGS) template.c

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


