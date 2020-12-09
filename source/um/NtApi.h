#ifndef __NT_API_H__
#define __NT_API_H__

extern "C" {

#define NTAPI   __stdcall

  typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
#ifdef MIDL_PASS
    [size_is(MaximumLength / 2), length_is((Length) / 2)] USHORT * Buffer;
#else // MIDL_PASS
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH   Buffer;
#endif // MIDL_PASS
  } UNICODE_STRING;
  typedef UNICODE_STRING *PUNICODE_STRING;
  typedef CONST UNICODE_STRING *PCUNICODE_STRING;

  typedef _Return_type_success_(return >= 0) LONG NTSTATUS;


  typedef struct _IO_STATUS_BLOCK {
    union {
      NTSTATUS Status;
      PVOID Pointer;
    } DUMMYUNIONNAME;

    ULONG_PTR Information;
  } IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

  typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
    PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
  } OBJECT_ATTRIBUTES;
  typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;


  NTSTATUS
    NTAPI
    NtCreateFile(
        _Out_ PHANDLE FileHandle,
        _In_ ACCESS_MASK DesiredAccess,
        _In_ POBJECT_ATTRIBUTES ObjectAttributes,
        _Out_ PIO_STATUS_BLOCK IoStatusBlock,
        _In_opt_ PLARGE_INTEGER AllocationSize,
        _In_ ULONG FileAttributes,
        _In_ ULONG ShareAccess,
        _In_ ULONG CreateDisposition,
        _In_ ULONG CreateOptions,
        _In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
        _In_ ULONG EaLength
    );

  typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
  } SECTION_INHERIT;

  NTSTATUS
    NTAPI
    NtMapViewOfSection(
        _In_ HANDLE SectionHandle,
        _In_ HANDLE ProcessHandle,
        _Outptr_result_bytebuffer_(*ViewSize) PVOID *BaseAddress,
        _In_ ULONG_PTR ZeroBits,
        _In_ SIZE_T CommitSize,
        _Inout_opt_ PLARGE_INTEGER SectionOffset,
        _Inout_ PSIZE_T ViewSize,
        _In_ SECTION_INHERIT InheritDisposition,
        _In_ ULONG AllocationType,
        _In_ ULONG Win32Protect
    );
#define OBJ_INHERIT                         0x00000002L
#define OBJ_PERMANENT                       0x00000010L
#define OBJ_EXCLUSIVE                       0x00000020L
#define OBJ_CASE_INSENSITIVE                0x00000040L
#define OBJ_OPENIF                          0x00000080L
#define OBJ_OPENLINK                        0x00000100L
#define OBJ_KERNEL_HANDLE                   0x00000200L
#define OBJ_FORCE_ACCESS_CHECK              0x00000400L
#define OBJ_IGNORE_IMPERSONATED_DEVICEMAP   0x00000800L
#define OBJ_DONT_REPARSE                    0x00001000L
#define OBJ_VALID_ATTRIBUTES                0x00001FF2L

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )  
#define ZwCurrentProcess() NtCurrentProcess()         
#define NtCurrentThread() ( (HANDLE)(LONG_PTR) -2 )   
#define ZwCurrentThread() NtCurrentThread()           
#define NtCurrentSession() ( (HANDLE)(LONG_PTR) -3 )  
#define ZwCurrentSession() NtCurrentSession()  


  // RTL_ to avoid collisions in the global namespace.
// I don't believe there are possible/likely constant RootDirectory
// or SecurityDescriptor values other than NULL, so they are hardcoded.
// As well, the string will generally be const, so we cast that away.
#define RTL_CONSTANT_OBJECT_ATTRIBUTES(n, a) \
    { sizeof(OBJECT_ATTRIBUTES), NULL, RTL_CONST_CAST(PUNICODE_STRING)(n), a, NULL, NULL }

// This synonym is more appropriate for initializing what isn't actually const.
#define RTL_INIT_OBJECT_ATTRIBUTES(n, a) RTL_CONSTANT_OBJECT_ATTRIBUTES(n, a)

#define FILE_SUPERSEDE                  0x00000000
#define FILE_OPEN                       0x00000001
#define FILE_CREATE                     0x00000002
#define FILE_OPEN_IF                    0x00000003
#define FILE_OVERWRITE                  0x00000004
#define FILE_OVERWRITE_IF               0x00000005
#define FILE_MAXIMUM_DISPOSITION        0x00000005

#define FILE_DIRECTORY_FILE                     0x00000001
#define FILE_WRITE_THROUGH                      0x00000002
#define FILE_SEQUENTIAL_ONLY                    0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING          0x00000008

#define FILE_SYNCHRONOUS_IO_ALERT               0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT            0x00000020
#define FILE_NON_DIRECTORY_FILE                 0x00000040
#define FILE_CREATE_TREE_CONNECTION             0x00000080

#define FILE_COMPLETE_IF_OPLOCKED               0x00000100
#define FILE_NO_EA_KNOWLEDGE                    0x00000200
#define FILE_OPEN_REMOTE_INSTANCE               0x00000400
#define FILE_RANDOM_ACCESS                      0x00000800

#define FILE_DELETE_ON_CLOSE                    0x00001000
#define FILE_OPEN_BY_FILE_ID                    0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT             0x00004000
#define FILE_NO_COMPRESSION                     0x00008000


#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

  NTSTATUS
    NTAPI
    NtCreateSection(
        _Out_ PHANDLE SectionHandle,
        _In_ ACCESS_MASK DesiredAccess,
        _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
        _In_opt_ PLARGE_INTEGER MaximumSize,
        _In_ ULONG SectionPageProtection,
        _In_ ULONG AllocationAttributes,
        _In_opt_ HANDLE FileHandle
    );

  NTSTATUS
    NTAPI
    NtClose(
        _In_ HANDLE Handle
    );

  typedef enum _KEY_INFORMATION_CLASS {
    KeyBasicInformation = 0,
    KeyNodeInformation = 1,
    KeyFullInformation = 2,
    KeyNameInformation = 3,
    KeyCachedInformation = 4,
    KeyFlagsInformation = 5,
    KeyVirtualizationInformation = 6,
    KeyHandleTagsInformation = 7,
    MaxKeyInfoClass = 8
  } KEY_INFORMATION_CLASS;

  typedef struct _KEY_NAME_INFORMATION {
    ULONG NameLength;
    WCHAR Name[1];
  } KEY_NAME_INFORMATION, *PKEY_NAME_INFORMATION;


  NTSTATUS
    NTAPI
    NtQueryKey(
        _In_       HANDLE KeyHandle,
        _In_       KEY_INFORMATION_CLASS KeyInformationClass,
        _Out_opt_  PVOID KeyInformation,
        _In_       ULONG Length,
        _Out_      PULONG ResultLength
    );

#define HASH_STRING_ALGORITHM_DEFAULT   (0)
#define HASH_STRING_ALGORITHM_X65599    (1)
#define HASH_STRING_ALGORITHM_INVALID   (0xffffffff)

  NTSTATUS
    NTAPI
    RtlHashUnicodeString(
      _In_  PCUNICODE_STRING String,
      _In_  BOOLEAN          CaseInSensitive,
      _In_  ULONG            HashAlgorithm,
      _Out_ PULONG           HashValue
    );

  NTSTATUS
    NTAPI
    NtLoadDriver(
      _In_ PUNICODE_STRING DriverServiceName
  );
  NTSTATUS
    NTAPI
    NtUnloadDriver(
      _In_ PUNICODE_STRING DriverServiceName
  );

  NTSTATUS
    NTAPI
    NtFreeVirtualMemory(
        _In_ HANDLE ProcessHandle,
        _Inout_ __drv_freesMem(Mem) PVOID *BaseAddress,
        _Inout_ PSIZE_T RegionSize,
        _In_ ULONG FreeType
    );

  extern "C++"
  {
    char _RTL_CONSTANT_STRING_type_check(const char *s);
    char _RTL_CONSTANT_STRING_type_check(const WCHAR *s);
    // __typeof would be desirable here instead of sizeof.
    template <size_t N> class _RTL_CONSTANT_STRING_remove_const_template_class;
    template <> class _RTL_CONSTANT_STRING_remove_const_template_class<sizeof(char)> { public: typedef  char T; };
    template <> class _RTL_CONSTANT_STRING_remove_const_template_class<sizeof(WCHAR)> { public: typedef WCHAR T; };
#define _RTL_CONSTANT_STRING_remove_const_macro(s) \
    (const_cast<_RTL_CONSTANT_STRING_remove_const_template_class<sizeof((s)[0])>::T*>(s))
  }

#define RTL_CONSTANT_STRING(s) \
{ \
    sizeof( s ) - sizeof( (s)[0] ), \
    sizeof( s ) / sizeof(_RTL_CONSTANT_STRING_type_check(s)), \
    _RTL_CONSTANT_STRING_remove_const_macro(s) \
}
}

#endif // !__NT_API_H__