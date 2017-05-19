
!IF "$(TARGETOS)" == "WINNT"

!include <win32.mak>

all: $(OUTDIR) $(OUTDIR)\CaptureCryptGenRandom.exe $(OUTDIR)\NextCryptGenOutputs.exe $(OUTDIR)\PreviousCryptGenOutputs.exe

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"


#======================================================================
# Define project specific macros
#======================================================================
PROJ_OBJS  = $(OUTDIR)\CaptureCryptGenRandom.obj $(OUTDIR)\NextCryptGenOutputs.obj $(OUTDIR)\PreviousCryptGenOutputs.obj $(OUTDIR)\simulator.obj
EXTRA_LIBS = crypt32.lib 


#======================================================================
# Inference rule for updating the object files
#======================================================================
$(OUTDIR)\CaptureCryptGenRandom.obj : CaptureCryptGenRandom.c
   $(cc) $(cdebug) $(cflags) $(cvarsdll) $(EXTRA_DEFS) /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" CaptureCryptGenRandom.c

$(OUTDIR)\NextCryptGenOutputs.obj : NextCryptGenOutputs.c
   $(cc) $(cdebug) $(cflags) $(cvarsdll) $(EXTRA_DEFS) /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" NextCryptGenOutputs.c

$(OUTDIR)\PreviousCryptGenOutputs.obj : PreviousCryptGenOutputs.c
   $(cc) $(cdebug) $(cflags) $(cvarsdll) $(EXTRA_DEFS) /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" PreviousCryptGenOutputs.c

$(OUTDIR)\SHA-1.obj : SHA-1.c
   $(cc) $(cdebug) $(cflags) $(cvarsdll) $(EXTRA_DEFS) /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" SHA-1.c

$(OUTDIR)\simulator.obj : simulator.c simulator.h
	$(cc) $(cdebug) $(cflags) $(cvarsdll) $(EXTRA_DEFS) /Fo"$(OUTDIR)\\" /Fd"$(OUTDIR)\\" simulator.c


#======================================================================
# Build Rules for EXE
#======================================================================
$(OUTDIR)\CaptureCryptGenRandom.exe : $(BASE_OBJS) $(OUTDIR)\CaptureCryptGenRandom.obj $(OUTDIR)\SHA-1.obj $(OUTDIR)\simulator.obj 
   $(link) $(ldebug) $(conlflags) $(OUTDIR)\CaptureCryptGenRandom.obj $(OUTDIR)\SHA-1.obj $(OUTDIR)\simulator.obj \
   $(conlibs) $(EXTRA_LIBS) -out:$(OUTDIR)\CaptureCryptGenRandom.exe 

$(OUTDIR)\NextCryptGenOutputs.exe : $(BASE_OBJS) $(OUTDIR)\NextCryptGenOutputs.obj $(OUTDIR)\SHA-1.obj $(OUTDIR)\simulator.obj
   $(link) $(ldebug) $(conlflags) $(OUTDIR)\NextCryptGenOutputs.obj $(OUTDIR)\SHA-1.obj $(OUTDIR)\simulator.obj\
   $(conlibs) -out:$(OUTDIR)\NextCryptGenOutputs.exe 

$(OUTDIR)\PreviousCryptGenOutputs.exe : $(BASE_OBJS) $(OUTDIR)\PreviousCryptGenOutputs.obj $(OUTDIR)\SHA-1.obj $(OUTDIR)\simulator.obj
   $(link) $(ldebug) $(conlflags) $(OUTDIR)\PreviousCryptGenOutputs.obj $(OUTDIR)\SHA-1.obj $(OUTDIR)\simulator.obj\
   $(conlibs) -out:$(OUTDIR)\PreviousCryptGenOutputs.exe 

clean :
	rm -rf WIN2000_DEBUG
    
!ELSE
!MESSAGE This sample requires the Microsoft Windows SDK to compile and run.
!MESSAGE Your shell may need to adjust several envrinment settings to compile:
!MESSAGE 1. Change directory to the SDK location 
!MESSAGE    (typically C:\Program Files\Microsoft Platform SDK)
!MESSAGE 2. Run VCVARS32.BAT from the Microsoft Visual Studio directory 
!MESSAGE    (typically C:\Program Files\Microsoft Visual Studio\VC98\Bin\)
!MESSAGE 3. Run "SETENV.CMD /2000"
!ENDIF 

