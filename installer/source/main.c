#include <ps4.h>

#include "defines.h"
#include "debug.h"
#include "offsets.h"

#define PS4_UPDATE_FULL_PATH "/update/PS4UPDATE.PUP"
#define PS4_UPDATE_TEMP_PATH "/update/PS4UPDATE.PUP.net.temp"

extern char kpayload[];
unsigned kpayload_size;

int install_payload(struct thread *td, struct install_payload_args* args)
{
	struct ucred* cred;
	struct filedesc* fd;
  uint64_t (*sceRegMgrSetInt)(uint32_t regId, int value);
  uint64_t (*sceRegMgrGetInt)(uint32_t regId, int OutValue);
	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;
	uint8_t* kernel_base = (uint8_t*)(__readmsr(0xC0000082) - XFAST_SYSCALL_addr);
	*(unsigned char*)(kernel_base + 0x212BDCD) = 0x82;
	*(unsigned char*)(kernel_base + 0x222898D) = 0x82;
  void(*sceSblSrtcClearTimeDifference)(uint64_t) = (void*)(kernel_base + 0x064C300);
	void(*sceSblSrtcSetTime)(uint64_t) = (void*)(kernel_base + 0x064CE20);
	sceSblSrtcClearTimeDifference(15);
	sceSblSrtcSetTime(14861963);
	uint8_t* kernel_ptr = (uint8_t*)kernel_base;
	void** got_prison0 = (void**)&kernel_ptr[PRISON0_addr];
	void** got_rootvnode = (void**)&kernel_ptr[ROOTVNODE_addr];
  *(void**)(&sceRegMgrSetInt) = &kernel_ptr[0x4FEFC0];
	*(void**)(&sceRegMgrGetInt) = &kernel_ptr[0x500280];	
	void (*pmap_protect)(void * pmap, uint64_t sva, uint64_t eva, uint8_t pr) = (void *)(kernel_base + pmap_protect_addr);
	void *kernel_pmap_store = (void *)(kernel_base + PMAP_STORE_addr);
	uint8_t* payload_data = args->payload_info->buffer;
	size_t payload_size = args->payload_info->size;
	struct payload_header* payload_header = (struct payload_header*)payload_data;
	uint8_t* payload_buffer = (uint8_t*)&kernel_base[DT_HASH_SEGMENT_addr];
	if (!payload_data || payload_size < sizeof(payload_header) || payload_header->signature != 0x5041594C4F414458ull)
		return -1;

	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;

	cred->cr_prison = *got_prison0;
  fd->fd_rdir = fd->fd_jdir = *got_rootvnode;
		
	// escalate ucred privs, needed for access to the filesystem ie* mounting & decrypting files
	void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred

	// sceSblACMgrIsSystemUcred
	uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
	*sonyCred = 0xffffffffffffffff;

	// sceSblACMgrGetDeviceAccessType
	uint64_t *sceProcType = (uint64_t *)(((char *)td_ucred) + 88);
	*sceProcType = 0x3801000000000013; // Max access

	// sceSblACMgrGetDeviceAccessType
	uint64_t *sceRemotePlay = (uint64_t *)(((char *)td_ucred) + 88);
	*sceRemotePlay = 0x3800000000000019; // SceRemotePlay
	
	// sceSblACMgrGetDeviceAccessType
	uint64_t *sceOSUPDATE = (uint64_t *)(((char *)td_ucred) + 88);
	*sceOSUPDATE = 0x3801000000000024; // sceOSUPDATE
	
	// sceSblACMgrGetDeviceAccessType
	uint64_t *scevtr = (uint64_t *)(((char *)td_ucred) + 88);
	*scevtr = 0x3800800000000002; // scevtr

	// sceSblACMgrGetDeviceAccessType
	uint64_t *NPXS20103 = (uint64_t *)(((char *)td_ucred) + 88);
	*NPXS20103 = 0x3800000000000011; // NPXS20103
	
	// sceSblACMgrIsAllowedToUseUNK_PFS
	uint64_t *UNK_PFS = (uint64_t *)(((char *)td_ucred) + 88);
	*UNK_PFS = 0x380100000000000A; // UNK_PFS

	// sceSblACMgrIsAllowedToUseUNK_ICC
	uint64_t *UNK_ICC = (uint64_t *)(((char *)td_ucred) + 88);
	*UNK_ICC = 0x3800800000000024; // UNK_ICC
	
	// sceSblACMgrIsAllowedToUsePupUpdate0
	uint64_t *PupUpdate0 = (uint64_t *)(((char *)td_ucred) + 88);
	*PupUpdate0 = 0x3800100000000001; // PupUpdate0
	
	// sceSblACMgrIsAllowedToUseSecureWebProcess
	uint64_t *SecureWebProcess = (uint64_t *)(((char *)td_ucred) + 88);
	*SecureWebProcess = 0x3800000010000003; // SecureWebProcess
	
	// sceSblACMgrIsAllowedToUseSceNKWebProcess
	uint64_t *SceNKWebProcess = (uint64_t *)(((char *)td_ucred) + 88);
	*SceNKWebProcess = 0x3800000000010003; // SceNKWebProcess

	// sceSblACMgrIsAllowedToUseSecureUIProcess
	uint64_t *SecureUIProcess = (uint64_t *)(((char *)td_ucred) + 88);
	*SecureUIProcess = 0x3800000000000033; // SecureUIProcess
	
	// sceSblACMgrIsAllowedToUseSceNKUIProcess
	uint64_t *SceNKUIProcess = (uint64_t *)(((char *)td_ucred) + 88);
	*SceNKUIProcess = 0x380000000000003c; // SceNKUIProcess
	
	// sceSblACMgrIsAllowedToUseSceSysAvControl
	uint64_t *SceSysAvControl = (uint64_t *)(((char *)td_ucred) + 88);
	*SceSysAvControl = 0x380000000000001; // SceSysAvControl

	// sceSblACMgrIsAllowedToUseSceShellUI
	uint64_t *SceShellUI = (uint64_t *)(((char *)td_ucred) + 88);
	*SceShellUI = 0x380000000000000f; // SceShellUI

	// sceSblACMgrIsAllowedToUseSceShellCore
	uint64_t *SceShellCore = (uint64_t *)(((char *)td_ucred) + 88);
	*SceShellCore = 0x3800000000000010; // SceShellCore

	// sceSblACMgrIsAllowedToUseDecid
	uint64_t *Decid = (uint64_t *)(((char *)td_ucred) + 88);
	*Decid = 0x3800000000010003; // Decid

	// sceSblACMgrGetDeviceSceVdecProxy
	uint64_t *SceVdecProxy = (uint64_t *)(((char *)td_ucred) + 88);
	*SceVdecProxy = 0x3800000000000003; // SceVdecProxy

	// sceSblACMgrGetDeviceSceVencProxy
	uint64_t *SceVencProxy = (uint64_t *)(((char *)td_ucred) + 88);
	*SceVencProxy = 0x3800000000000004; // SceVencProxy
	
	// sceSblACMgrGetDeviceOrbisaudiod
	uint64_t *Orbisaudiod = (uint64_t *)(((char *)td_ucred) + 88);
	*Orbisaudiod = 0x3800000000000005; // Orbisaudiod
	
	// sceSblACMgrGetDeviceCoredump
	uint64_t *Coredump = (uint64_t *)(((char *)td_ucred) + 88);
	*Coredump = 0x3800000000000006; // Coredump

	// sceSblACMgrGetDeviceOrbissetip
	uint64_t *Orbissetip = (uint64_t *)(((char *)td_ucred) + 88);
	*Orbissetip = 0x3800000000000008; // Orbissetip

	// sceSblACMgrIsAllowedToUseGnmCompositor
	uint64_t *GnmCompositor = (uint64_t *)(((char *)td_ucred) + 88);
	*GnmCompositor = 0x3800000000000009; // GnmCompositor

	// sceSblACMgrIsAllowedToUseSceGameLiveStreaming
	uint64_t *SceGameLiveStreaming = (uint64_t *)(((char *)td_ucred) + 88);
	*SceGameLiveStreaming = 0x3800000000000012; // SceGameLiveStreaming
	
	// sceSblACMgrIsAllowedToUseSCE_SYS_SERVICES
	uint64_t *SCE_SYS_SERVICES = (uint64_t *)(((char *)td_ucred) + 88);
	*SCE_SYS_SERVICES = 0x3800000000010003; // SCE_SYS_SERVICES
	
	// sceSblACMgrIsAllowedToUseScePartyDaemon
	uint64_t *ScePartyDaemon = (uint64_t *)(((char *)td_ucred) + 88);
	*ScePartyDaemon = 0x3800000000000014; // ScePartyDaemon

	// sceSblACMgrIsAllowedToUseSceAvCapture
	uint64_t *SceAvCapture = (uint64_t *)(((char *)td_ucred) + 88);
	*SceAvCapture = 0x3800000000000015; // SceAvCapture
	
	// sceSblACMgrIsAllowedToUseSceVideoCoreServer
	uint64_t *SceVideoCoreServer = (uint64_t *)(((char *)td_ucred) + 88);
	*SceVideoCoreServer = 0x3800000000000016; // SceVideoCoreServer	

	// sceSblACMgrIsAllowedToUsemini_syscore
	uint64_t *mini_syscore = (uint64_t *)(((char *)td_ucred) + 88);
	*mini_syscore = 0x3800000000000022; // mini_syscore

	// sceSblACMgrIsAllowedToUseSceCloudClientDaemon
	uint64_t *SceCloudClientDaemon = (uint64_t *)(((char *)td_ucred) + 88);
	*SceCloudClientDaemon = 0x3800000000000028; // SceCloudClientDaemon
	
	// sceSblACMgrIsAllowedToUsefs_cleaner
	uint64_t *fs_cleaner = (uint64_t *)(((char *)td_ucred) + 88);
	*fs_cleaner = 0x380000000000001d; // fs_cleaner	

	// sceSblACMgrIsAllowedToUseSceSocialScreenMgr
	uint64_t *SceSocialScreenMgr = (uint64_t *)(((char *)td_ucred) + 88);
	*SceSocialScreenMgr = 0x3800000000000037; // SceSocialScreenMgr

	// sceSblACMgrIsAllowedToUseSceSpZeroConf
	uint64_t *SceSpZeroConf = (uint64_t *)(((char *)td_ucred) + 88);
	*SceSpZeroConf = 0x380000001000000E; // SceSpZeroConf

	// sceSblACMgrIsAllowedToUseSceMusicCoreServer
	uint64_t *SceMusicCoreServer = (uint64_t *)(((char *)td_ucred) + 88);
	*SceMusicCoreServer = 0x380000000000001a; // SceMusicCoreServer

	// sceSblACMgrIsAllowedToUsesceSblACMgrHasUseHp3dPipeCapability
	uint64_t *sceSblACMgrHasUseHp3dPipeCapability = (uint64_t *)(((char *)td_ucred) + 88);
	*sceSblACMgrHasUseHp3dPipeCapability = 0x3800000010000009; // sceSblACMgrHasUseHp3dPipeCapability

	// sceSblACMgrIsAllowedToUsesceSblACMgrHasUseHp3dPipeCapability2
	uint64_t *sceSblACMgrHasUseHp3dPipeCapability2 = (uint64_t *)(((char *)td_ucred) + 88);
	*sceSblACMgrHasUseHp3dPipeCapability2 = 0x380100000000002C; // sceSblACMgrHasUseHp3dPipeCapability2
	
	// sceSblACMgrIsAllowedToUseSceSysCore
	uint64_t *SceSysCore = (uint64_t *)(((char *)td_ucred) + 88);
	*SceSysCore = 0x3800000000000007; // SceSysCore	
				
	// sceSblACMgrHasSceProcessCapability
	uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
	*sceProcCap = 0xffffffffffffffff; // Sce Process

	sceRegMgrSetInt(0x3C040000, 0);
  sceRegMgrGetInt(0x3C040000, 0);

	// Disable write protection
	uint64_t cr0 = readCr0();
	writeCr0(cr0 & ~X86_CR0_WP);
	
  uint8_t *kmem;

  //setloginpatch                   
 	/*kmem = (uint8_t *)(kernel_base + 0x0037CF6C);
	kmem[0] = 0x48;
	kmem[1] = 0x31;
	kmem[2] = 0xC0;
	kmem[3] = 0x90;
	kmem[4] = 0x90;
		 
  //panic
 	kmem = (uint8_t *)(kernel_base + 0x046D11E);
	kmem[0] = 0x90;
	kmem[1] = 0x90;
	kmem[2] = 0x90;
	kmem[3] = 0x90;
	kmem[4] = 0x90;
	
  // Patch setuid: Don't run kernel exploit more than once/privilege escalation
	kmem = (uint8_t *)(kernel_base + 0x037A320);
	kmem[0] = 0xB8;
	kmem[1] = 0x00;
	kmem[2] = 0x00;
	kmem[3] = 0x00;
	kmem[4] = 0x00;*/
	kmem = (uint8_t *)(kernel_base + global_settings_base);
	kmem[0x36] |= 0x14;
	kmem[0x59] |= 0x01;
	kmem[0x59] |= 0x02;
	kmem[0x5A] |= 0x01;
	kmem[0x78] |= 0x01;
	
	// Patch debug setting errors
	kmem = (uint8_t *)(kernel_base + debug_menu_error_patch1);
	kmem[0] = 0x00;
	kmem[1] = 0x00;
	kmem[2] = 0x00;
	kmem[3] = 0x00;

	kmem = (uint8_t *)(kernel_base + debug_menu_error_patch2);
	kmem[0] = 0x00;
	kmem[1] = 0x00;
	kmem[2] = 0x00;
	kmem[3] = 0x00;
	
	// flatz disable pfs signature check
	kmem = (uint8_t *)(kernel_base + disable_signature_check_patch);
	kmem[0] = 0x31;
	kmem[1] = 0xC0;
	kmem[2] = 0xC3;

	// flatz enable debug RIFs
	kmem = (uint8_t *)(kernel_base + enable_debug_rifs_patch1);
	kmem[0] = 0xB0;
	kmem[1] = 0x01;
	kmem[2] = 0xC3;

	kmem = (uint8_t *)(kernel_base + enable_debug_rifs_patch2);
	kmem[0] = 0xB0;
	kmem[1] = 0x01;
	kmem[2] = 0xC3;

	// Patch sys_dynlib_dlsym: Allow from anywhere
	kmem = (uint8_t *)(kernel_base + 0x004523C4);
	kmem[0] = 0xE9;
	kmem[1] = 0xC8;
	kmem[2] = 0x01;
	kmem[3] = 0x00;
	kmem[4] = 0x00;
	
	// Enable *all* debugging logs (in vprintf)
	// Patch by: SiSTRo
	kmem = (uint8_t *)(kernel_base + enable_debug_log_patch);
	kmem[0] = 0xEB;
	kmem[1] = 0x3B;

	// Enable UART
	kmem = (uint8_t *)(kernel_base + enable_uart_patch);
	kmem[0] = 0x00;
  	
	// install kpayload
	memset(payload_buffer, 0, PAGE_SIZE);
	memcpy(payload_buffer, payload_data, payload_size);
	
  uint64_t sss = ((uint64_t)payload_buffer) & ~(uint64_t)(PAGE_SIZE-1);
	uint64_t eee = ((uint64_t)payload_buffer + payload_size + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE-1);
	kernel_base[pmap_protect_p_addr] = 0xEB;
	pmap_protect(kernel_pmap_store, sss, eee, 7);
	kernel_base[pmap_protect_p_addr] = 0x75;

	// Restore write protection
	writeCr0(cr0);

	int (*payload_entrypoint)();
	*((void**)&payload_entrypoint) = (void*)(&payload_buffer[payload_header->entrypoint_offset]);

	return payload_entrypoint();
}

static inline void patch_update(void)
{
	unlink(PS4_UPDATE_FULL_PATH);
	unlink(PS4_UPDATE_TEMP_PATH);

	mkdir(PS4_UPDATE_FULL_PATH, 777);
	mkdir(PS4_UPDATE_TEMP_PATH, 777);
}

int _main(struct thread *td) 
{
	int result;

	initKernel();
	initLibc();
	
#ifdef DEBUG_SOCKET
	initNetwork();
	initDebugSocket();
#endif

	printfsocket("Starting...\n");

	struct payload_info payload_info;
	payload_info.buffer = (uint8_t *)kpayload;
	payload_info.size = (size_t)kpayload_size;

	errno = 0;

	result = kexec(&install_payload, &payload_info);
	result = !result ? 0 : errno;
	printfsocket("install_payload: %d\n", result);

	patch_update();

	initSysUtil();
	notify("Silver-Hen-U-"VERSION"                       "DEV);

	printfsocket("Done.\n");

#ifdef DEBUG_SOCKET
	closeDebugSocket();
#endif

	return result;
}