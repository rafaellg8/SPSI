CFLAGS   = /c /AL /G3 /DMSDOS               # controls compiler options
LFLAGS   = /ST:16000 /NOI /NOE              # controls linker options

OBJS = tinykey.obj isprime.obj commode.obj

all : tinykey.exe

tinykey.exe : $(OBJS)
    link $(LFLAGS) @<<tinykey.lrf
$(OBJS: =+^
)
tinykey.exe
tinykey.map;
<<KEEP

tinykey.obj : tinykey.c 
     CL $(CFLAGS) tinykey.c

isprime.obj : isprime.c
     CL $(CFLAGS) isprime.c

commode.obj:

clean :
    -del *.obj
    -del *.map
    -del *.lrf


