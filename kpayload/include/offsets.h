#ifndef __OFFSETS_H__
#define __OFFSETS_H__
#pragma once
// 7.55

// data
#define	XFAST_SYSCALL_addr              0x000001C0
#define M_TEMP_addr                     0x01556DA0
#define MINI_SYSCORE_SELF_BINARY_addr   0x015A8FC8
#define ALLPROC_addr                    0x0213C828
#define SBL_DRIVER_MAPPED_PAGES_addr    0x02662648
#define SBL_PFS_SX_addr                 0x0267C040
#define SBL_KEYMGR_KEY_SLOTS_addr       0x02684238
#define SBL_KEYMGR_KEY_RBTREE_addr      0x02684248
#define SBL_KEYMGR_BUF_VA_addr          0x02688000
#define SBL_KEYMGR_BUF_GVA_addr         0x02688808
#define FPU_CTX_addr                    0x02689740
#define DIPSW_addr                      0x02228950

// common
#define memcmp_addr                     0x0031D250
#define _sx_xlock_addr                  0x000D1600
#define _sx_xunlock_addr                0x000D17C0
#define malloc_addr                     0x001D6680
#define free_addr                       0x001D6870
#define strstr_addr                     0x003B0250
#define fpu_kern_enter_addr             0x004A5260
#define fpu_kern_leave_addr             0x004A5350
#define memcpy_addr                     0x0028F800
#define memset_addr                     0x0008D6F0
#define strlen_addr                     0x002E8BC0
#define printf_addr                     0x0026F740
#define eventhandler_register_addr      0x000D3670

// Fself
#define sceSblACMgrGetPathId_addr       0x00364D80
#define sceSblServiceMailbox_addr       0x0064A1A0
#define sceSblAuthMgrSmIsLoadable2_addr 0x0065C090
#define _sceSblAuthMgrGetSelfInfo_addr  0x0065C8E0
#define _sceSblAuthMgrSmStart_addr      0x00655C50
#define sceSblAuthMgrVerifyHeader_addr  0x0065C0F0

// Fpkg
#define RsaesPkcs1v15Dec2048CRT_addr    0x001517F0
#define Sha256Hmac_addr                 0x00274740
#define AesCbcCfb128Encrypt_addr        0x0021F810
#define AesCbcCfb128Decrypt_addr        0x0021FA40
#define sceSblDriverSendMsg_0_addr      0x00634A40
#define sceSblPfsSetKeys_addr           0x0063F100
#define sceSblKeymgrSetKeyStorage_addr  0x0063E3E0
#define sceSblKeymgrSetKeyForPfs_addr   0x00643B20
#define sceSblKeymgrCleartKey_addr      0x00643E80
#define sceSblKeymgrSmCallfunc_addr     0x006436F0

// Patch
#define vmspace_acquire_ref_addr        0x002FC290
#define vmspace_free_addr               0x002FC0C0
#define vm_map_lock_read_addr           0x002FC430
#define vm_map_unlock_read_addr         0x002FC480
#define vm_map_lookup_entry_addr        0x002FCA70
#define proc_rwmem_addr                 0x00361310

// Fself hooks
#define sceSblAuthMgrIsLoadable__sceSblACMgrGetPathId_hook          0x0065A51C
#define sceSblAuthMgrIsLoadable2_hook                               0x0065A66E
#define sceSblAuthMgrVerifyHeader_hook1                             0x0065AE06
#define sceSblAuthMgrVerifyHeader_hook2                             0x0065BAE9
#define sceSblAuthMgrSmLoadSelfSegment__sceSblServiceMailbox_hook   0x006580FD
#define sceSblAuthMgrSmLoadSelfBlock__sceSblServiceMailbox_hook     0x00658D48

// Fpkg hooks
#define sceSblKeymgrSetKeyStorage__sceSblDriverSendMsg_hook         0x0063E485
#define sceSblKeymgrInvalidateKey__sx_xlock_hook                    0x00644CFD
#define sceSblKeymgrSmCallfunc_npdrm_decrypt_isolated_rif_hook      0x006667D0
#define sceSblKeymgrSmCallfunc_npdrm_decrypt_rif_new_hook           0x0066759E
#define mountpfs__sceSblPfsSetKeys_hook1                            0x006D9757
#define mountpfs__sceSblPfsSetKeys_hook2                            0x006D9988

// SceShellUI patches - debug patches
#define sceSblRcMgrIsAllowDebugMenuForSettings_patch                0x0001D140
#define sceSblRcMgrIsStoreMode_patch                                0x0001D4A0

// SceShellUI patches - remote play patches
#define CreateUserForIDU_patch                                      0x0018E120
#define remote_play_menu_patch                                      0x00EC66E1

// SceRemotePlay patches - remote play patches
#define SceRemotePlay_patch1                                        0x0010A13A
#define SceRemotePlay_patch2                                        0x0010A155

// SceShellCore patches
// call sceKernelIsGenuineCEX
#define sceKernelIsGenuineCEX_patch1    0x00168A90
#define sceKernelIsGenuineCEX_patch2    0x007FBF00
#define sceKernelIsGenuineCEX_patch3    0x0084AF42
#define sceKernelIsGenuineCEX_patch4    0x009D3150

// call nidf_libSceDipsw
#define nidf_libSceDipsw_patch1         0x00168ABA
#define nidf_libSceDipsw_patch2         0x00316BD3
#define nidf_libSceDipsw_patch3         0x007FBF2A
#define nidf_libSceDipsw_patch4         0x009D317A

// enable data mount
#define enable_data_mount_patch         0x00316BC3

// enable fpkg
#define enable_fpkg_patch               0x003C244F
 
// debug pkg free string
#define fake_free_patch                 0x00F66831

// make pkgs installer working with external hdd
#define pkg_installer_patch             0x009BC141

// enable support with 6.xx external hdd
#define ext_hdd_patch1                  0x005BCF2D
#define ext_hdd_patch2                  0x00133080

// enable debug trophies on retail
#define debug_trophies_patch            0x0071759B

// disable screenshot block
#define disable_screenshot_patch        0x0038C8B6

#define enable_psvr_patch               0x00D57E60

// 'sce_sdmemory' patch
//#define sce_sdmemory_patch				      0x01600060
 
//verify keystone patch
//#define verify_keystone_patch			      0x0087F840

//#define ssc_sceKernelIsAssistMode

#define sceSblACMgrIsAllowedSystemLevelDebugging1  0x00364CD0
#define sceSblACMgrIsAllowedSystemLevelDebugging2  0x00364D40
#define sceSblACMgrIsAllowedSystemLevelDebugging3  0x00364D60

// Enable rwx mapping
#define sys_rwx_map                     0x001754AC 
#define sys_rwx_map1                    0x001754B4

// patch mprotect to allow RWX (mprotect) mapping 7.55
#define sys_rwx_patch                   0x003014C8

// Patch to remove vm_fault: fault on nofault entry, addr %llx
#define sys_vm_fault_patch              0x003DF2A6

// Patch by: JOGolden
#define sys_patchA                      0x0028FD12
#define sys_patchB                      0x0028FD21

//#define setloginpatch                   0x0037CF6C

//#define sys_setuid                      0x0037A320

// ptrace patches 909090909090
#define ptrace_patches                  0x0016FA34

// Patch copyinstr
#define copyinstr_patches               0x0028FEF3
// second copyinstr patch  
#define copyinstr2_patches              0x0028FEFF
// copyin
#define copyin_patches                  0x0028FA47
// second copyin patch  
#define copyin2_patches                 0x0028FA53	
// copyout
#define copyout_patches                 0x0028F952
// second copyout patch  
#define copyout2_patches                0x0028F95E

// Verbose Panics
//#define Panic                           0x0046D11E

// Map-Self
#define map_self1                       0x00364D40
#define map_self2                       0x00364D60
#define map_self3                       0x000DCED1

#define memcpy_stack                    0x0028F80D

// ptrace patches EB
//#define ptrace2_patches                 0x00361CF5
// ptrace patches E97C020000
#define ptrace3_patches                 0x003621CF

#define aslr_patches                    0x00218AF4
#define C3_patches                      0x0077F9A0

// Enable mount for unprivileged user
#define sys_mount_unprivileged_user     0x00076385

#define sys_map                         0x000DB17D

// allow sys_dynlib_dlsym in all processes 90E9
//#define sys_dynlib_dlsym_patch1         0x004523C4

//allow sys_dynlib_dlsym 31C0C3
#define sys_dynlib_dlsym_patch2         0x00029A30

// flatz allow mangled symbol in dynlib_do_dlsym 909090909090
#define sys_dynlib_dlsym_patch3         0x000271A7

#define Send_sysveri                0x00636850
#define Fuck                        0x00637380
#define sceSblSysVeriInitialize     0x00636600
#define sceVeri                     0x00636DB0
	// Clear the sceVeri initialized flag
#define sceVeri_initialized         0x02662B00

//#define spoof         0x02662B00
#endif