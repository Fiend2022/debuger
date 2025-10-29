# Makefile ��� ������ debugger_core.dll ��� x86 � x64
# �������������:
#   nmake /f Makefile ARCH=x64
#   nmake /f Makefile ARCH=x86
#   nmake /f Makefile clean

!IFNDEF ARCH
ARCH = x64
!ENDIF

# ���� � vcpkg (�������� ��� �������������)
VCPKG_ROOT = C:\vcpkg

!IF "$(ARCH)" == "x64"
VCPKG_TRIPLET = x64-windows
MACHINE = x64
!ELSEIF "$(ARCH)" == "x86"
VCPKG_TRIPLET = x86-windows
MACHINE = x86
!ELSE
!ERROR ���������������� �����������: $(ARCH). ����������� ARCH=x86 ��� ARCH=x64.
!ENDIF

VCPKG_INCLUDE = $(VCPKG_ROOT)\installed\$(VCPKG_TRIPLET)\include
VCPKG_LIB = $(VCPKG_ROOT)\installed\$(VCPKG_TRIPLET)\lib

SOURCES = DebugAPI.cpp DebugCore.cpp EventPublisher.cpp pe.cpp
OBJECTS = $(SOURCES:.cpp=.obj)

DLL_NAME = DebugCore$(ARCH).dll
LIB_NAME = DebugCore$(ARCH).lib

CXXFLAGS = /std:c++17 /EHsc /MD /I. /I"$(VCPKG_INCLUDE)" /DNDEBUG
LDFLAGS = /DLL /MACHINE:$(MACHINE) /OUT:$(DLL_NAME)

LIBS = kernel32.lib user32.lib "$(VCPKG_LIB)\libudis86.lib"

all: $(DLL_NAME)

.cpp.obj:
	$(CXX) /c $(CXXFLAGS) $<

$(DLL_NAME): $(OBJECTS)
	link $(LDFLAGS) $(OBJECTS) $(LIBS)

clean:
	del *.obj $(DLL_NAME) $(LIB_NAME) *.exp 2>nul

both: 
	nmake /f Makefile.make ARCH=x86
	nmake /f Makefile.make ARCH=x64

.PHONY: all clean both