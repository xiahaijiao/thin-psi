# Compiler flags...
CPP_COMPILER = g++
C_COMPILER = gcc
PSI_SO_Name=libPSI_Linux-2021-04-24-dynamic.so

# Include paths...
Debug_Include_Path=-I"../openssl/include"
Release_Include_Path=-I"../openssl/include" 

# Library paths...
Debug_Library_Path=-L"../openssl/lib" -L"/opt/jdk1.8.0_261/lib"
Release_Library_Path=-L"../openssl/lib"  -L"/opt/jdk1.8.0_261/lib"  

# Additional libraries...
Debug_Libraries=-Wl,--start-group -lcrypto -Wl,--end-group
Release_Libraries=-Wl,--start-group -lcrypto  -Wl,--end-group

# Preprocessor definitions...

Release_Preprocessor_Definitions=-D GCC_BUILD -D NDEBUG -D _LINUX -D _USRDLL -D PSI_Linux_EXPORTS 

# Implictly linked object files...
Debug_Implicitly_Linked_Objects=
Release_Implicitly_Linked_Objects=

# Compiler flags...
Debug_Compiler_Flags=-fPIC -O0 -g 
Release_Compiler_Flags=-fPIC -O2 

# Builds all configurations for this project...
.PHONY: build_all_configurations
build_all_configurations:Release 
 
# Builds the Release configuration...
.PHONY: Release
Release: create_folders x64/gccRelease/com_rongan_PSINativeRA.o x64/gccRelease/RAPSIUtil.o x64/gccRelease/RAPSIUtilOpenSSL.o 
	g++ -fPIC -shared -Wl,-soname,$(PSI_SO_Name) -o ../x64/gccRelease/$(PSI_SO_Name) x64/gccRelease/com_rongan_PSINativeRA.o x64/gccRelease/RAPSIUtil.o x64/gccRelease/RAPSIUtilOpenSSL.o $(Release_Libraries) $(Release_Implicitly_Linked_Objects)

# Compiles file com_rongan_PSINativeRA.cpp for the Release configuration...
-include x64/gccRelease/com_rongan_PSINativeRA.d
x64/gccRelease/com_rongan_PSINativeRA.o: com_rongan_PSINativeRA.cpp
	$(CPP_COMPILER) $(Release_Preprocessor_Definitions) $(Release_Compiler_Flags) -c com_rongan_PSINativeRA.cpp $(Release_Include_Path) -o x64/gccRelease/com_rongan_PSINativeRA.o
	$(CPP_COMPILER) $(Release_Preprocessor_Definitions) $(Release_Compiler_Flags) -MM com_rongan_PSINativeRA.cpp $(Release_Include_Path) > x64/gccRelease/com_rongan_PSINativeRA.d

# Compiles file RAPSIUtil.cpp for the Release configuration...
-include x64/gccRelease/RAPSIUtil.d
x64/gccRelease/RAPSIUtil.o: RAPSIUtil.cpp
	$(CPP_COMPILER) $(Release_Preprocessor_Definitions) $(Release_Compiler_Flags) -c RAPSIUtil.cpp $(Release_Include_Path) -o x64/gccRelease/RAPSIUtil.o
	$(CPP_COMPILER) $(Release_Preprocessor_Definitions) $(Release_Compiler_Flags) -MM RAPSIUtil.cpp $(Release_Include_Path) > x64/gccRelease/RAPSIUtil.d


# Compiles file RAPSIUtilOpenSSL.cpp for the Release configuration...
-include x64/gccRelease/RAPSIUtilOpenSSL.d
x64/gccRelease/RAPSIUtilOpenSSL.o: RAPSIUtilOpenSSL.cpp
	$(CPP_COMPILER) $(Release_Preprocessor_Definitions) $(Release_Compiler_Flags) -c RAPSIUtilOpenSSL.cpp $(Release_Include_Path) -o x64/gccRelease/RAPSIUtilOpenSSL.o
	$(CPP_COMPILER) $(Release_Preprocessor_Definitions) $(Release_Compiler_Flags) -MM RAPSIUtilOpenSSL.cpp $(Release_Include_Path) > x64/gccRelease/RAPSIUtilOpenSSL.d


# Creates the intermediate and output folders for each configuration...
.PHONY: create_folders
create_folders:
	mkdir -p gccRelease
	mkdir -p x64/gccRelease
	mkdir -p ../x64/gccRelease

# Cleans intermediate and output files (objects, libraries, executables)...
.PHONY: clean
clean:
	rm -f gccRelease/*.o
	rm -f gccRelease/*.d
	rm -f x64/gccRelease/*.o
	rm -f x64/gccRelease/*.d
	rm -f ../x64/gccRelease/*.a
	rm -f ../x64/gccRelease/*.so
	rm -f ../x64/gccRelease/*.dll
	rm -f ../x64/gccRelease/*.exe

