ifndef RESTBED_MODULES_PATH
export RESTBED_MODULES_PATH=/usr/src/assets/restbed
endif

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= SIM
SGX_ARCH ?= x64

CxX=g++-4.9

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
	SGX_COMMON_CFLAGS += -O0 -g
else
	SGX_COMMON_CFLAGS += -O2
endif

######## App Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

App_Cpp_Files := app/app.cpp
App_Include_Paths := -I$(SGX_SDK)/include -Iapp -I. -I$(RESTBED_MODULES_PATH)/distribution/include

App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC $(App_Include_Paths)

ifeq ($(SGX_DEBUG), 1)
	App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
	App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

App_Cpp_Flags := $(App_C_Flags) -std=c++11 -c -Wall -Wno-sign-compare -Wno-char-subscripts -Wno-unused-variable
App_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -L$(RESTBED_MODULES_PATH)/distribution/library -lrestbed -L. -lsgx_ukey_exchange -lsgx_tcrypto -lpthread -Wl,-rpath=$(CURDIR)

ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_uae_service_sim
else
	App_Link_Flags += -lsgx_uae_service
endif

App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)

App_Name := client

######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto

Enclave_Cpp_Files := enclave/enclave.cpp
Enclave_SP_Cpp_Files := enclave_sp/enclave_sp.cpp
Enclave_Include_Paths := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport

Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths)
Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++03 -nostdinc++ -Wall
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx -lsgx_tkey_exchange -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=enclave/enclave.lds

Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)

Enclave_Name := enclave.so

Signed_Enclave_Name := enclave.signed.so
Enclave_Config_File := enclave/enclave.config.xml

ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE
endif
endif
endif


.PHONY: all run

ifeq ($(Build_Mode), HW_RELEASE)
all: $(App_Name) $(Enclave_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(App_Name) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool. See User's Guide for more details."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
all: $(App_Name) $(Signed_Enclave_Name)
endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(App_Name)
	@echo "RUN  =>  $(App_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

######## App Objects ########

app/enclave_u.c: $(SGX_EDGER8R) enclave/enclave.edl
	@cd app && $(SGX_EDGER8R) --untrusted ../enclave/enclave.edl --search-path ../enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

app/enclave_u.o: app/enclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

app/%.o: app/%.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(App_Name): app/enclave_u.o $(App_Cpp_Objects)
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

######## Enclave Objects ########

enclave/enclave_t.c: $(SGX_EDGER8R) enclave/enclave.edl
	@cd enclave && $(SGX_EDGER8R) --trusted ../enclave/enclave.edl --search-path ../enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

enclave/enclave_t.o: enclave/enclave_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

enclave/%.o: enclave/%.cpp
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Enclave_Name): enclave/enclave_t.o $(Enclave_Cpp_Objects)
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key enclave/enclave_private.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"

enclave_sp/enclave_sp_t.c: $(SGX_EDGER8R) enclave_sp/enclave_sp.edl
	@cd enclave_sp && $(SGX_EDGER8R) --trusted ../enclave_sp/enclave_sp.edl --search-path ../enclave_sp --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

enclave_sp/enclave_sp_t.o: enclave_sp/enclave_sp_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

enclave_sp/%.o: enclave_sp/%.cpp
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

.PHONY: clean

clean:
	@rm -f $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_Cpp_Objects) app/enclave_u.* $(Enclave_Cpp_Objects) enclave/enclave_t.*
