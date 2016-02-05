CFLAGS   = /c /AL /G3 /Oilt /DMSDOS /DSMALL_MEM /DNO_ASM 
LFLAGS   = /ST:16000 /NOI /NOE       

OBJS = otpf.obj crypt.obj tempfile.obj nextfile.obj getopt.obj crypth.obj commode.obj

all : otpf.exe

otpf.exe : $(OBJS)
    link $(LFLAGS) @<<otpf.lrf
$(OBJS: =+^
)
otpf.exe
otpf.map;
<<KEEP

crypt.obj: crypt.c crypt.h getopt.h nextfile.h tempfile.h
     CL $(CFLAGS) crypt.c

otpf.obj : otpf.c crypt.h tempfile.h
     CL $(CFLAGS) otpf.c

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


