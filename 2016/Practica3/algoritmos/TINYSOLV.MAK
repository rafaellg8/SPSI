CFLAGS   = /c /AL /G3 /DMSDOS               # controls compiler options
LFLAGS   = /ST:16000 /NOI /NOE              # controls linker options

OBJS = tinysolv.obj isprime.obj commode.obj

all : tinysolv.exe

tinysolv.exe : $(OBJS)
    link $(LFLAGS) @<<tinysolv.lrf
$(OBJS: =+^
)
tinysolv.exe
tinysolv.map;
<<KEEP

tinysolv.obj : tinysolv.c
     CL $(CFLAGS) tinysolv.c

isprime.obj : isprime.c
     CL $(CFLAGS) isprime.c

commode.obj:

clean :
    -del *.obj
    -del *.map
    -del *.lrf


