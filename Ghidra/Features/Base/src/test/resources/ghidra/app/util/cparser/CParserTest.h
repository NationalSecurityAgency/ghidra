/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/** Test parsing header file for CParser.  Most of the file is just checked to make sure it gets through parsing.
 ** Some data types are checked.  More checking of the parsed information would be beneficial at some point.
 **/


/**
 * Check initial anonymous __func_1, is give an name blarg
 *  Note: This must be first function for junit tests to pass
 **/

void blarg(int *, long[][][]);

/**
 ** Function typedef use in function body
 **/
typedef int ExternFunc(int);
    
void testFunc()
{
    ExternFunc * func = (ExternFunc*)0;
}

void testFunc()
{
    typedef int InternFunc(int);
    
    InternFunc * func = (InternFunc *) 0;
}


 /**
 * Test arrays of anonymous functions in a structure
 **/
typedef struct SomeStruct {
   int first_member;
   int *second_member[3];
   char (*procArray1[2])(int *, short *);
   int anotherMember;
   int (*procArray2[2])(int *, int *);
   int (*LoneProc1)(char, int);
   int (*LoneProc2)(char, int);
   int finalMember;
} SomeStruct;


/**
 * Test forward declaration
 **/
 typedef struct ThisStruct {
     ThisStruct *prev;
     struct ThisStruct *next;
} ThisStruct;

 typedef struct _ThatStruct {
     _ThatStruct *prev;
     struct ThatStruct *next;
} ThatStruct;


/**
 * Test name used as field
 */
struct fieldname {
        unsigned char a, b, c;
};

struct mainname {
        unsigned int field1;
        struct fieldname fieldname[256];    // field with same name as struct name
};


/**
 *   Anonymous function parameter definitions
 **/
void funcParam(void (*)(void));

void funcParmWithName(void (*_func_arg)(void));

double funcParamNoPtr(double x, double func(double, void *));

double funcParam1( double, double (*)( double ) );
double funcParam2( double, double( double ) );  // this guy _func_
double funcParam3( const double, double (*)( double ) );
double funcParam4( const double, double( double ) );  // this guy _func_
double funcParam5( double, double (*)( const double ) );
double funcParam6( double, double( const double ) ); // this guy _func_
double funcParam7( const double, double (*)( const double ) );
double funcParam8( const double, double( const double ) );  // this guy _func_
double funcParam9(double, double (* const)(double ) );
double funcParam10(double, double (__cdecl *)(double ) );


typedef unsigned int size_t;

typedef unsigned long size_t;

void* __cdecl memset(
     void*  _Dst,
                              int    _Val,
                              size_t _Size
    );

typedef size_t rsize_t;
 
static __inline int __cdecl memcpy_s(
         void*       const _Destination,
         rsize_t     const _DestinationSize,
         void const* const _Source,
         rsize_t     const _SourceSize
        ) {
                if (_SourceSize == 0)
        {
            return 0;
        }
        memset(_Destination, 0, _DestinationSize);
}
        
 void __mem_func (void *, char **, int ***, long (*) (size_t),
                                      short *(*) (size_t),
                                      void *(*) (void *, size_t));

 void * foo;

 typedef void *bar;

 typedef int size_t;
 typedef int pid_t;


typedef long _Once_t;
void __cdecl _Once(_Once_t *, void (__cdecl *)(void));

void __stdcall _Twice(void (__cdecl *)(void));

void _Thrice(void (__cdecl *)(void));

/**
 ** use of long as an attribute
 **/
typedef long unsigned int LUI_size_t;
typedef unsigned long int ULI_size_t;
typedef long signed   int LSI_size_t;
typedef long          int LI_size_t;
typedef long long     int LLI_size_t;
typedef long unsigned long int LULI_size_t;
typedef unsigned long long int ULLI_size_t;
typedef long long unsigned int LLUI_size_t;
typedef unsigned int  UI_size_t;

/**
 ** pragma usage
 **/
int (__stdcall * GetSectionBlock) (
        int section,
        long len,
        long align=1,
        void **ppBytes=0) ;


 #pragma region Input compatibility macros

   #pragma warning(disable)

  #pragma warning(disable:4035 4793)               // re-enable below

   #pragma section(".CRTMP$XCA",long,read)

#pragma GCC poison (*(volatile uint8_t *)(0xB3))
 
 #pragma our macros nachos (for use only within FileProvider.h)
 
 #pragma warning (suppress: 28128)

int g(int a, int b, int c)
{
    return a+b+c;
}
int f(void)
{
    return g(1,
        2,3);
}

int f(void)
{
    return g(1,
#pragma warning (suppress: 28128)
        2,3);
}



/**
 ** Packing tests
 **/
 #pragma pack(push,2)

 #pragma pack(push, PlaceHolder)

 #pragma pack(push, 4)

 __pragma(pack(push, MyName, 8))
struct __declspec(align(16)) __pragma(warning(push)) __pragma(warning(disable:4845)) __declspec(no_init_all) __pragma(warning(pop)) packed8 {
    char a;
    short b;
    int c;
    long d;
    long long e;
};
__pragma(pack(pop, MyName))

struct packed4 {
    char a;
    char b;
    char c;
    int d;
};

#pragma pack(pop, PlaceHolder)


struct packed2 {
    char a;
    int  d;
};
#pragma pack(pop)

#pragma pack(1)

struct packed1 {
    char a;
};

#pragma pack(push);
#pragma pack(1);
#pragma pack(pop);

#pragma pack();  // reset to none

struct packed_none {
   char a;
};


/**
 ** Bitfield tests
 **/
struct BitFields1 {
	char a:1;
	char b:2;
	char c:3;
	char d:1;
};

struct BitFields2 {
	char a:1;
	char b:2;
	char c:3;
	char d:4;
};

struct BitFields3 {
	char a:1;
	char b:2;
	char c:3;
	int  i:11;
	char d:1;
	char e:8;
};

struct BitFields4 {
	   unsigned long n0:4;
	   unsigned long n1:4;
	   unsigned long n2:4;
	   unsigned long n3:4;
	   unsigned long n4:4;
	   unsigned long n5:4;
	   unsigned long n6:4;
	   unsigned long n7:4;
	   unsigned long n8:4;
	   unsigned long n9:4;
	   unsigned long n10:4;
	   unsigned long n11:4;
	   unsigned long n12:4;
	   unsigned long n13:4;
	   unsigned long n14:4;
	   unsigned long n15:4;
};

union BitFields5 {
	char a:1;
	char b:2;
	char c:3;
	short  i:11;
	char d:1;
	short s;
	char e:8;
	int f:23;
};

union wait
{
  int w_status;
  struct
  {
	unsigned int t:7;
	unsigned int c:1;
	unsigned int r:8;
	unsigned int:16;
  } __wait_terminated;
  struct
  {
	unsigned int v:8;
	unsigned int s:8;
	unsigned int:0;
	unsigned int:8;
	unsigned int:8;
  } __wait_stopped;
};


 #pragma once

packed4 *
__stdcall
 dtAfterPragma(int);

/**
 ** unnamed function decl in param
 **/
typedef long _Once_t;
void __cdecl _Once(_Once_t *, void (__cdecl *)(void));


/**
 ** typdef data type definition and usage
 **/
typedef int     *memory_object_info_t;
typedef int      memory_object_flavor_t;
typedef int      memory_object_info_data_t[(1024)];

typedef void range_t(int, void *, unsigned type, void *, unsigned);

typedef struct introspect_t {
    void (*enumerator)(int task, void *, unsigned type_mask, int zone_address, int reader, range_t recorder);
} introspect_t;


typedef void (event_fun) (unsigned int type,  void *arg,
                             unsigned int arg_size, void *user_data);

extern int select_events (unsigned int mask,
								event_fun *callback,
                                  void *callback_data);

int testForUseOfTypedef(int a, int b, int c) {
	callOther(a, xp_event_fun, b);
}

int      fputs( char * , void * ) __asm("_" "fputs" "$FPOOTS");

void     _exit(int) __attribute__((noreturn));

// NoReturn

extern void gcc_exit (int __status) __attribute__ ((__noreturn__));

__declspec(noreturn) void __cdecl win_exit(int _Code);

void     _exit(int) __attribute__((noreturn));

// C11 noreturn
void     _Noreturn _Noreturn_exit(int);


// C23 Attributes
int      [[deprecated]] imDeprecated(int);
int      [[gnu::deprecated]] imDeprecatedToo(int) ;
int      [[deprecated("bad design")]] imDeprecatedToo(int) ;
int      [[deprecated("bad design")]] imDeprecatedToo(int) ;

[[gnu::always_inline]] [[gnu::hot]] [[gnu::const]] [[nodiscard]]
int f(void); // declare f with four attributes
 
[[gnu::always_inline, gnu::const, gnu::hot, nodiscard]]
int f(void); // same as above, but uses a single attr specifier that contains four attributes
 
 
// __attribute__
int      abs(int) __attribute__((bob));

enum __attribute__((enum_extensibility(open))) OpenEnum {
  B0, B1
};

typedef int (__cdecl * _onexit_t)(void);

typedef int int32_t;
typedef long int64_t;

static __inline __attribute__((always_inline)) int
__checkint(int val, int* err) {
        if (val < (-2147483647-1) || val > 2147483647) {
                *err |= OVR_ERR;
        }

        val = 8 * sizeof(val);

        return (int32_t) val;
}


/**
 ** Structure extension
 **/
struct __declspec(align(8)) System_Exception_Fields {
    int _HResult;
};

struct System_SystemException_Fields : System_Exception_Fields {
     int foo;
};

struct System_System_SystemException_Fields : System_SystemException_Fields {
     int foo;
     short bar;
};

typedef enum {} EmptyEnum;


typedef struct fstruct;

typedef int (*fnptr)(struct fstruct);



/**
 ** function declarations in a structure
 **/
struct {
int ( __stdcall *Initialize )(
    void * This,
int *pUnkAD,
int ( __stdcall __DHelper0000 )(
        void *pv),
void *pPool);

int ( __stdcall *DoCallback )(
    void * This,
int *pUnkAD,
int ( __stdcall __DHelper0001 )(
        void *pv),
void *pPool);

} IDHelperVtbl;



struct fowstruct {
    fstruct *next;
};


@protocol  Bubba
bob
marley
@end

@protocol SwiftProtocol
@required
- (void) method;
@end

typedef struct __attribute__ ((packed))
{
    int test1;
    int test2;
}testStruct;


int bob(int b);


typedef unsigned long long int ULONGLONG;
typedef long long int LONGLONG;
typedef int DWORD;


typedef void (__stdcall COOLBACK)(int hdrvr, int uMsg, int * dwUser, int * dw1, int * dw2);

typedef COOLBACK  *LPCOOLBACK;

typedef COOLBACK     *PCOOLBACK;

 typedef int size_t;
 typedef int pid_t;

/* struct cbs  */
struct cbs
{
  int (*init) (void);
  int (*m_init) (void **p);
  int (*m_destroy) (void **p);
  int (*m_lock) (void **p);
  int (*m_unlock) (void **p);
  size_t (*read) (int fd, void *buf, size_t nbytes);
  size_t (*write) (int fd, const void *buf, size_t nbytes);
};

/**
 ** Union tests
 **/
 typedef union sigval
  {
    int sival_int;
    void *sival_ptr;
  } sigval_t;

typedef struct sigevent
  {
    sigval_t sigev_value;
    int sigev_signo;
    int sigev_notify;

    union {
	   int _pad[((64 / sizeof (int)) - 3)];


	   int _tid;

	   struct
	   {
	    void (*_function) (sigval_t);
	    void *_attribute;
	   } _sigev_thread;
    } _sigev_un;
  } sigevent_t;


/*
 * Complicated sizeof array size
 */
typedef struct
{
    unsigned long int val[(1024 / (8 * sizeof (unsigned long int)))];
} sizeof_t;


typedef unsigned long int __cpu_mask;

typedef struct
{
  __cpu_mask __bits[1024 / (8 * (int) sizeof (__cpu_mask))];
  char       szUrl[(2048 + 32 + sizeof("://"))] ;
} cpu_set_t;


typedef struct testStruct
{
    char test[8];
} *pTestStruct;

int testFunction(pTestStruct ptr)
{
	struct cpu_set_t cpset;

    int a = sizeof(ptr->test);
    int b = sizeof(ptr);
    int c = sizeof(cpset.__bits);

    return a;
}

struct _IO_FILE_complete
{
 size_t __pad5;
 int _mode;
 /* Make sure we don't get into trouble again.  */
 char _unused2[15 * sizeof (int) - 4 * sizeof (void **) - sizeof (size_t)];
};


 void __mem_func (void *, char **, int ***, long (*) (size_t),
                                      short *(*) (size_t),
                                      void *(*) (void *, size_t));

typedef unsigned short int UShortInt;
typedef unsigned long long ULongLong;
typedef signed long long SLongLong;
typedef long long LongLong;
typedef signed short int SShortInt;
typedef short int ShortInt;

typedef union { unsigned char __c[8]; double __d; } __huge_val_t;

static __huge_val_t __huge_val = { { 0, 0, 0, 0, 0, 0, 0xf0, 0x7f } };

typedef unsigned int error_t;

static inline error_t
make_error (error_t source, error_t code)
{
  char x = L'x';

  return 1;
}

extern unsigned char AsciiTable[][8];

unsigned short int __bswap_16 (unsigned short int __bsx)
{
  return ((((__bsx) >> 8) & 0xff) | (((__bsx) & 0xff) << 8));
}

struct bob {
  int a;
  int b;
};


/**
 ** struct allocation with sizeof
 **/
struct sockaddr_in
  {
    int sin_family;
    int sin_port;
    struct in_addr sin_addr;


    unsigned char sin_zero[3 * sizeof (struct bob) -
			   (sizeof (unsigned short int)) -
			   sizeof (int) -
			   sizeof (struct bob)];
  };

struct __step;
struct __step_data;
struct __load_object;
struct __trans_data;
typedef int size_t;


typedef int (*__gconv_fct) (struct __step *, struct __step_data *,
			    const unsigned char **, const unsigned char *,
			    unsigned char **, size_t *, int, int);


typedef union __declspec(intrin_type) __declspec(align(8)) __m64
{
    unsigned __int64    m64_u64;
    float               m64_f32[2];
    __int8              m64_i8[8];
    __int16             m64_i16[4];
    __int32             m64_i32[2];
    __int64             m64_i64;
    unsigned __int8     m64_u8[8];
    unsigned __int16    m64_u16[4];
    unsigned __int32    m64_u32[2];
} __m64;



extern __m64 _mm_loadh_pi1(__m64, const __m64 *);
extern __m64 _mm_loadh_pi2(__m64, __m64 const *);

__cdecl int cdecl_func(const int a);

int __cdecl cdecl_func_after(const int a);

int __stdcall stdcall_func(int b);

// test default structure alignment
struct inner {
	char  ca;
	short sa;
};

struct outer {
	char ca;
	short sa;           //  @2
	struct inner ia;    //  @4
	char cb;            //  @8
	struct inner ib;    //  @10
	int cc;             //  @16
};

 typedef char wctype_t;

 const wctype_t * __cdecl __pwctype_func(void);

 const unsigned short * __cdecl __pctype_func(void);

 extern const unsigned short *_pctype;

 extern const unsigned short _wctype[];


 extern const wctype_t *_pwctype;


typedef long int32_t;

extern int bob(int a);

typedef int baz[8][6];

void * IOPRepLoss(void *, void *, void *);

typedef unsigned short int UINT2;

typedef unsigned long POINTER_64_INT;


typedef unsigned int DWORD;

typedef struct _IFEntry {
    DWORD BeginAddr;
    DWORD EndAddr;
    DWORD UnwindInfoAddr;
} _IFEntry, *_pIFENtry;


typedef signed char         INT8, *PINT8;
typedef signed short        INT16, *PINT16;
typedef signed int          INT32, *PINT32;
typedef signed __int64      INT64, *PINT64;
typedef unsigned char       UINT8, *PUINT8;
typedef unsigned short      UINT16, *PUINT16;
typedef unsigned int        UINT32, *PUINT32;
typedef unsigned __int64    UINT64, *PUINT64;


typedef signed int LONG32, *PLONG32;

typedef unsigned int ULONG32, *PULONG32;
typedef unsigned int DWORD32, *PDWORD32;


typedef __w64 int INT_PTR, *PINT_PTR;
typedef __w64 unsigned int UINT_PTR, *PUINT_PTR;

typedef __w64 long LONG_PTR, *PLONG_PTR;
typedef __w64 unsigned long ULONG_PTR, *PULONG_PTR;

typedef unsigned short UHALF_PTR, *PUHALF_PTR;
typedef short HALF_PTR, *PHALF_PTR;
typedef __w64 long SHANDLE_PTR;
typedef __w64 unsigned long HANDLE_PTR;


__inline
void * __ptr64
PtrToPtr64(
    const void *p
    )
{
    return((void * __ptr64) (unsigned __int64) (ULONG_PTR)p );
}

__inline
void *
Ptr64ToPtr(
    const void * __ptr64 p
    )
{
    return((void *) (ULONG_PTR) (unsigned __int64) p);
}

__inline
void * __ptr64
HandleToHandle64(
    const void *h
    )
{
    return((void * __ptr64) h );
}

/**
 * Test const before / after TypeName
**/
typedef long long TEST_TYPE_A;

void funcA(TEST_TYPE_A const * arg);

void funcB(void)
{
    funcA((const TEST_TYPE_A *)0);
}

void funcB(void)
{
    funcA((TEST_TYPE_A const *)0);
}


/**
 **  pragma usage
 **/
__pragma(warning(push))
__pragma(warning(disable: 6014))
__declspec(noalias) __inline void __cdecl _freea(    void * _mem)
{
    unsigned int _mark;
    if (_mem)
    {
        __pragma(warning(push));
        _mem = (char*)_mem - 8;
        _mark = *(unsigned int *)_mem;

        if (_mark == 0xDDDD)
        {
            free(_mem);
        }
        else if (_mark != 0xCCCC)
        {
            ((void)0);
        }
        __pragma(warning(pop));
    }
}

__pragma(warning(pop))

__inline     void _set_daylight(int day)     {         __pragma(warning(push))         __pragma(warning(disable:4996))         (*__nightTime()) = day;         __pragma(warning(pop))     }



int    __cdecl atexit(void (*)(void));

/**
 ** Array sizes with flex array
 **/
typedef struct _arraysInStruct
 {
        unsigned long A,B,C,D;
        unsigned long data4[64>>3];
        unsigned long flexOne[0];
        unsigned long data16[(64/(4))];
        unsigned int num;
        unsigned long flexTwo[0];
} ArraysInStruct;

struct EmptyBuffer {
	int x;
	char buf[];
};


/**
 ** Array Size allocation with expression
 **/
struct ivd {
        char type[(1-1+1)];
        char id[(6-2+1)];
        char version[(7-7+1)];
        char data[(2048-8+1)];
};


struct precedence {
        char oneA[1-1+1];
        char oneB[(1 << 1 >> 1)];
        char version[1 - (1 >> 1 << 1)];
        char data[(2048-8+1)];
};

/**
 ** Calculated Enum values
 **/
enum options_enum {
    DOBACKGROUND		= 1 << 0,

    DONEBACKROUND	= 1 << 1,

    SUPPORTED		= 1 << 2,

	/* one up value */

	ONE_UP,

	PLUS_SET   =    4 + 12,
	
	PLUS_SET   =    4 + 12,
	
#pragma endit

	MINUS_SET   =    12 - 1,

	SHIFTED1 = 1 << 1 >> 1,

	SHIFTED3 = 7 >> 3 << 3,

	SHIFTED4 = 15 >> 3 << 3,

	ISONE = 1 - 1 + 1,

	ISNEGATIVE = -5-1,

	BIGNUM = 64 * 16 + 16,

	TRINARY =  (0 ? 10 : 11),
};

/**
 ** Predeclare Enum
 **/
 
typedef enum _PARAM_TYPE PARAM_TYPE;

typedef int FuncUseEnum(PARAM_TYPE ptype);

typedef enum _PARAM_TYPE { A, B, C } PARAM_TYPE;


/**
 ** Casting
 **/
char * retInitedStorage(int i)
{
  char foo[3] = { 'a', 'b', 'c'};

  return  (char *) (void) { 'a', 'b', 'c'};
}

typedef float __m128 __attribute__ ((__vector_size__ (16), __may_alias__));


typedef float __v4sf __attribute__ ((__vector_size__ (16)));

extern __inline __m128 __attribute__((__gnu_inline__, __always_inline__, __artificial__))
_mm_set1_ps (float __F)
{
  return  (__m128) {0, 1, 2, 3};
}


/**
 ** Structure Initializers / casting
 **/
struct { int a[3], b; } w[] =
{
   { { 1, 0, 0 }, 0 },
   { { 2, 0, 0 }, 0 }
};

int *ptr = (int *){ 10, 20, 30, 40 };

struct s {
    int   x;
    float y;
    char  *z;
};

struct s pi = (struct s){ 3, 3.1415, "Pi" };

struct s fs_pi = (struct s){ .z = "Pi", .x = 3, .y = 3.1415 };

struct { int a[3], b; } w[] = { [0].a = {1}, [1].a[0] = 2 };


/**
 ** _Alignas
 **/
 
 // every object of type struct data will be aligned to 128-byte boundary
struct data {
  char x;
  _Alignas(128) char cacheline[128]; // over-aligned array of char, 
                                    // not array of over-aligned chars
};

int aligning(void)
{
    int sof = sizeof(struct data);
    int aof = _Alignof(struct data);
    
    printf("sizeof(data) = %zu \n", sizeof(struct data));
 
    printf("alignment of data = %zu\n", _Alignof(struct data));
 
    _Alignas(2048) struct data d; // this instance of data is aligned even stricter
}

typedef long long LRESULT;

typedef LRESULT (__stdcall* WNDPROC)(HWND, UINT, WPARAM, LPARAM);


/**
 ** declspec directive
 **/
__declspec(deprecated("abc" "def"))
void old_function(void);

__declspec(deprecated("The POSIX name for this item is deprecated. Instead, use the ISO C++ conformant name: " #_inpw ".")) unsigned short __cdecl inpw(unsigned short);

__declspec(deprecated("The POSIX name for this item is deprecated. Instead, use the ISO C++ conformant name: " #_getch() "."))  int __cdecl getch(void);


__declspec(deprecated("This function || variable has been superceded by newer library || functionality. Consider using " #Bat " instead. See online help for details.")) int __cdecl _BatBall( char * name);
__declspec(deprecated("This function || variable has been superceded by newer library || functionality. Consider using " #LA " instead. See online help for details.")) int __cdecl _LARun(  int a);
__declspec(deprecated("This function || variable has been superceded by newer library || functionality. Consider using " #GetA " instead. See online help for details.")) int (__cdecl * __cdecl _DoGood(  int a, char * name, int oort))(void);


extern "C" __declspec(dllexport) int __cdecl bobCRef(int a, const fstruct &fs, struct fstruct *fp);


typedef unsigned int __uint32_t;

/**
 ** far pointer keyword use
 **/
struct arm_exception_state
{
	__uint32_t	exception;
	__uint32_t	fsr;
	__uint32_t  far;
};


/**
 ** Assembly Parsing
 **/
__forceinline
long
readInLine (
     int count
    )
{
    int i = 1;
    int b = 0;
    int c = 50;

    __asm _volatile_ {
        mov ecx, count
        ret
    };
}


__inline void * doIt( void ) { __asm {
                                        mov eax, fs:[0x500]
                                        mov eax,[eax]
                                        };
                                     }

__inline long
__stdcall
iMod (
     int v,
     int sc
    )
{
    __asm {
        mov     ecx, sc
        mov     eax, dword ptr [v]
        mov     edx, dword ptr [v+20]
        pop     edx, ebx
    }
}

__inline int * accessT( void ) { __asm mov eax, fs:[0x8] }


__forceinline
long
getOut (
    void
    )
{
    __asm rdtsc
}

__forceinline
void
assertFail (
    void
    )
{
    __asm int 0x2e
}


/**
 ** More assembly block parsing (ignoring)
 **/
typedef int size_t;

void simple_gnu_asm()
{
	asm(".intel_syntax noprefix");
	asm ("call .L1         \n\t"
	     ".L1:             \n\t"
	     "addw [esp],6     \n\t"
	     "ret              \n\t"
	);
	asm("ret":::);
	asm(".att_syntax noprefix");
}

unsigned long __readfsdword(unsigned long Offset)
{
	unsigned long ret;
	__asm__ (
		"mov{" "l" " %%" "fs" ":%[offset], %[ret] | %[ret], %%" "fs" ":%[offset]}"
		: [ret] "=r" (ret)
		: [offset] "m" ((int)Offset)
	);
	return ret;
}

typedef int size_t;

unsigned long __readfsdword2(unsigned long Offset) { unsigned long ret; __asm__ ("mov{" "l" " %%" "fs" ":%[offset], %[ret] | %[ret], %%" "fs" ":%[offset]}" : [ret] "=r" (ret) : [offset] "m" ((*(unsigned long *) (size_t) Offset)) ); return ret; }

unsigned char _interlockedbittestandset(long *Base, long Offset)
{
	unsigned char old;
	__asm__  (
		"lock bts{l %[Offset],%[Base] | %[Base],%[Offset]} ; setc %[old]"
		: [old] "=qm" (old), [Base] "+m" (*Base)
		: [Offset] "I" "r" "w" (Offset)
		: "memory", "cc"
	);
	return old;
}

extern __inline__ __attribute__((__always_inline__,__gnu_inline__))
unsigned char _interlockedbittestandset64(long long volatile *Base, long long Offset) { unsigned char old; __asm__ __volatile__ ("lock bts{q %[Offset],%[Base] | %[Base],%[Offset]}" "\n\tsetc %[old]" : [old] "=qm" (old), [Base] "+m" (*Base) : [Offset] "J" "r" (Offset) : "memory" , "cc"); return old; }

/**/

/**
 ** Multi-Line String constants
 **/
 
void singleLineStrings(void)
{
    char a[] = "Hello " "World";
}
void multilineStrings(void)
{
    char b[] = "This is a "
               "multiline string.";
}
 


/**
 ** #line in structure/function body
 **/

#line 1 "C:source/repos/ghidra_preprocess/structif.h"

typedef struct mystruct {

#line 8 "C:source/repos/ghidra_preprocess/structif.h"

  int a;

#line 8 "C:source/repos/ghidra_preprocess/structif.h"
};
#line 9 ""


char lineInFunc(int i) {
 #line 1 "first/line.h"
 int j;

 #line 2 "second/line.h"
     return 'a';
 #line 3 "third/line.h"
 }
 

/**
 ** Check _Static_assert support
 **/
#line 1 "static_assert.h"
int check_assert(void)
{
	// test with message
    _Static_assert(1 + 2 + 3 < 6, "With message");
    static_assert(1 + 1 != 2, "math fail!");

    // test no message
    _Static_assert(sizeof(int) < sizeof(char));
    static_assert(sizeof(int) < sizeof(char));

    int x;
    static_assert(sizeof(int) > sizeof(char));
}

struct statcheck {
   int a;
   static_assert(1 + 1 == 3, "1 + 1 == 3, fail!");
   int b;
};

typedef int test_before;
static_assert(1 + 1 == 2, "That's true!");
typedef int test_after;
