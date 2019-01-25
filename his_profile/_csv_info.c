
/*
c99 -Wc,asm,lp64,ascii,exportall,gonum,list -Wl,dll,lp64 -I$CONDA_PREFIX/include/python3.6m -DPYTHON -o _csv_info.so _csv_info.c $CONDA_PREFIX/lib/libpython3.6m.x > _csv_info.list

 */

#pragma comment(copyright, "Copyright Rocket Software, Inc. 2018, 2019")

#include "Python.h"
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct modi_1 {
  void * __ptr32 rb;
  char name8[8];
  void * __ptr32 ep; /* HOB means 31 bit amode, LOB means 64 bit mode */
  unsigned char reserved1[4];
  unsigned short use_count;
  unsigned char attr1;
  unsigned char subpool;
  unsigned char attr2;
#define MODI_MINOR 0x04
  unsigned char attr3;
  unsigned char attr4;
#define MODI_PATHNAME 0x80 /* epname */
  unsigned char reserved2;
  unsigned char xflags[8];
  unsigned char reserved3[4];
  void *ep64;
  unsigned char dskey[8];
  unsigned char pathtoken[12];
  unsigned char reserved4[2];
  unsigned short dyn_lpa_pathname_len;
  char * __ptr32 dyn_lpa_pathname;
};

struct modi_2 {
  int number;
  /* int segment_length[number]; */
  /* void * __ptr32 segment_address[number]; */
};

struct modi64_1 {
  int number;
  int reserved;
  void *segment_address;
  long segment_length;
};

struct modi_3 {
  unsigned short name_length;
  unsigned short asid;
  int provider_id;
  unsigned char provider_data[16];
  unsigned char ep_token[8];
  char ep_name[1];
};

struct modi_4 {
  unsigned short load_count;
  unsigned short load_syscount;
};

struct modi_5 {
  char major_name8[8];
};

struct modi_header {
  char id[4]; /* MODI */
  unsigned char userdata[16];
  void * __ptr32 abdpl;
  struct modi_1 * __ptr32 modi_1_ptr; /* 1 to 5 */
  int modi_1_len;
  struct modi_2 * __ptr32 modi_2_ptr;
  int modi_2_len;
  struct modi_3 * __ptr32 modi_3_ptr;
  int modi_3_len;
  struct modi_4 * __ptr32 modi_4_ptr;
  int modi_4_len;
  struct modi_5 * __ptr32 modi_5_ptr;
  int modi_5_len;
  unsigned int flags;
  struct modi64_1 * __ptr32 modi64_1_ptr;
  int modi64_1_len;
};

struct csvinfo {
  char version;                /* 0x00 */
  unsigned char xflags1;       /* 0x01 */
  /* (HOB first) FUNC_JPA, FUNC_LPA, FUNC_TASKLOAD, FUNC_TASKALL, FUNC_RB, ENV_MVS, ENV_IPCS */
  unsigned short asid;         /* 0x02 */
  void * __ptr32 abdpl_ptr;    /* 0x04 */ 
  char reserved[8];            /* 0x08 */
  struct mipr *  __ptr32 mipr; /* 0x10 */
  unsigned char userdata[16];  /* 0x14 */
  void * __ptr32 tcb;          /* 0x34 */
  void * __ptr32 rb;           /* 0x38 */ 
};

struct call_csvinfo {
  void *regs64_0[16];
  void *regs64_1[16];
  struct csvinfo csvinfo;
  struct {int r15; int r0;} r15_r0;
  struct csvinfo * __ptr32 csvinfo_ptr;
};

/* addr_begin, addr_end, and name are all null the first time the callback is called with a given header */
/* after the first call, all three values are non-NULL */
typedef int (call_csvinfo_callback)(void *info, struct modi_header *header, void *addr_begin, void *addr_end, char *name, int name_length, int type);

static unsigned char mff_1_1[] = {0x47, 0xF0};
/* LE standard ep    0x47, 0xF., 0x.., 0x..,  0x00, 0xC3, 0xC5, 0xC5,  stackframesize,  offset to ppa1 */
/* LE standard PPA1  1 byte offset (in bytes) to name */
static unsigned char mff_1_2[] = {0x00, 0xC3, 0xC5, 0xC5};
/* LE fastlink ep    0x47, 0xF., 0x.., 0x..,  0x01, 0xC3, 0xC5, 0xC5,  stackframesize,  offset to ppa1 */
/* LE fastlink PPA1  1 byte offset (in 2 bytes) to name */
static unsigned char mff_1_3[] = {0x01, 0xC3, 0xC5, 0xC5};
static unsigned char mff_1_4[] = {0x00, 0xC3, 0x00, 0xC5, 0x00, 0xC5};

/* CCN */
static unsigned char mff_2_1[] = {0x00, 0xC3, 0x00, 0xC3, 0x00, 0xD5, 0x01, 0x00};
static unsigned char mff_2_2[] = {0x90, 0xEC};

/* LE xplink   ep-16 0x00, 0xC3, 0x00, 0xC5,  0x00, 0xC5, 0x00, 0xF1,  offset to ppa1 */
static unsigned char mff_3_1[] = {0x00, 0xC3, 0x00, 0xC5, 0x00, 0xC5, 0x00, 0xF1};

static int count = 0;

#define TYPE_LoadEnd              0xF
#define TYPE_Function_LE_Standard 0xE
#define TYPE_Function_LE_Fastlink 0xD
#define TYPE_Function_LE_CCN      0xC
#define TYPE_Function_LE_XPLINK   0xB
#define TYPE_Source               0xA
#define TYPE_LoadPathname         0x9
#define TYPE_Load_major_and_minor 0x8
#define TYPE_Load                 0x7
#define TYPE_Boundary             0x6
#define TYPE_Function_NOT_LE 0

static int find_functions(call_csvinfo_callback *callback, void *info, struct modi_header *header, void *caddr_in, long clen)
{
  if (0) fprintf(stdout, "find_functions: addr=%016lX len=%08lX\n", caddr_in, clen);
  int result = 0;
  char cname[8];
  unsigned char *csect_name = NULL;
  unsigned short file_name_length = 0;
  char *file_name = NULL;
  unsigned char *beginning_of_csect = NULL;
  unsigned char *end_of_csect = NULL;
  unsigned char *c_name_ptr = NULL;
  unsigned char *prev_c_name_ptr = NULL;
  char have_name = 0;
  char prev_have_name = 0;
  unsigned char *caddr_begin = (unsigned char *)caddr_in;
  unsigned char *caddr_end = (unsigned char *)caddr_in + clen;
  if (0) {fprintf(stdout, "%016lX %016lX\n", caddr_begin, caddr_end); fflush(stdout);}
  unsigned char *prev_caddr = NULL;
  unsigned char *prev_ppa4_ptr = NULL;
  int prev_type = 0;
  for (unsigned char *caddr = caddr_begin; caddr <= caddr_end; caddr += 2) {
    char type = 0;
    unsigned char *ppa1_ptr = NULL;
    unsigned char *ppa2_ptr = NULL;
    unsigned char *ppa4_ptr = NULL;
    int offset_to_name = 0;
    if (caddr == caddr_end) {
      if (prev_caddr && prev_c_name_ptr) {
	unsigned short name_length = *(unsigned short *)prev_c_name_ptr;
	char *name = (char *)prev_c_name_ptr + sizeof(unsigned short);
	result = (*callback)(info, header, prev_caddr, caddr, name, name_length, prev_type);
	if (result) return result;
      }
      type = TYPE_LoadEnd;
    } else {
      if (end_of_csect && caddr >= end_of_csect) {
	if (prev_caddr && prev_c_name_ptr) {
	  unsigned short name_length = *(unsigned short *)prev_c_name_ptr;
	  char *name = (char *)prev_c_name_ptr + sizeof(unsigned short);
	  result = (*callback)(info, header, prev_caddr, caddr, name, name_length, prev_type);
	  if (result) return result;
	}
	beginning_of_csect = NULL;
	end_of_csect = NULL;
	csect_name = NULL;
	prev_c_name_ptr = NULL;
      }
      if (0) {
      } else if (0 == memcmp(caddr+0, mff_1_1, sizeof(mff_1_1)) &&
		 0 == memcmp(caddr+4, mff_1_2, sizeof(mff_1_2)) &&
		 0 != memcmp(caddr+12, mff_1_4, sizeof(mff_1_4))) {
	prev_c_name_ptr = c_name_ptr;
	ppa1_ptr = caddr + *(int *)(caddr + 12);
	if (ppa1_ptr >= caddr_begin && ppa1_ptr < caddr_begin) {
	  offset_to_name = ppa1_ptr[0]; 
	  type = TYPE_Function_LE_Standard;
	} else {
	  ppa1_ptr = NULL; /* SVMTCBGO 08/14/09.08.20 HDZ1C10.HDZ1C10.VER=1.12 */
	  type = TYPE_Function_NOT_LE;
	}
      } else if (0 == memcmp(caddr+0, mff_1_1, sizeof(mff_1_1)) &&
		 0 == memcmp(caddr+4, mff_1_3, sizeof(mff_1_3)) &&
		 0 != memcmp(caddr+12, mff_1_4, sizeof(mff_1_4))) {
	prev_c_name_ptr = c_name_ptr;
	ppa1_ptr = caddr + *(int *)(caddr + 12);
	if (ppa1_ptr >= caddr_begin && ppa1_ptr < caddr_begin) {
	  offset_to_name = ppa1_ptr[0] * 2; 
	  type = TYPE_Function_LE_Fastlink;
	} else {
	  ppa1_ptr = NULL;
	}
      } else if ((caddr + 0x14) < caddr_end &&
		 0 == memcmp(caddr, mff_2_1, sizeof(mff_2_1)) &&
                 0 == memcmp(caddr + 0x10, mff_2_2, sizeof(mff_2_2))) {
	ppa1_ptr = caddr + *(int *)(caddr + 8);
	type = TYPE_Function_LE_CCN;
      } else if ((caddr + 0x10) < caddr_end &&
		 0 == memcmp(caddr+0, mff_3_1, sizeof(mff_3_1))) {
	ppa1_ptr = caddr + *(int *)(caddr + 8);
	type = TYPE_Function_LE_XPLINK;
      }	
    }
    if (ppa1_ptr) {
      char name_is_present = ppa1_ptr[11] & 0x01;
      char info_type = ppa1_ptr[10];
      if (*(int *)ppa1_ptr == 0) {
        offset_to_name = 4;
        type = TYPE_Function_NOT_LE;
      }
      if (type == TYPE_Function_LE_XPLINK || type == TYPE_Function_LE_CCN) {
        offset_to_name = 0x14;
        for (int i=1; i<0x100; i = i<<1) {
          if (info_type & i)
            offset_to_name += 4;
        }
        if (info_type & 0x30)
          offset_to_name += 4;
        if (info_type & 0x01)
          offset_to_name += 4;
        if (ppa1_ptr[11] & 0x20)
          offset_to_name += 8;
      }
      if (type == TYPE_Function_LE_Standard)
	ppa2_ptr = (unsigned char *)*(int *)(ppa1_ptr+4);
      else if (type == TYPE_Function_LE_Fastlink)
	ppa2_ptr = caddr_begin + *(int *)(ppa1_ptr+4);
      else if (type == TYPE_Function_LE_XPLINK || type == TYPE_Function_LE_CCN)
	ppa2_ptr = ppa1_ptr + *(int *)(ppa1_ptr+4);
      if (ppa2_ptr) {
	ppa4_ptr = ppa2_ptr + *(int *)(ppa2_ptr+8);
      }
      if (ppa4_ptr && ppa4_ptr != prev_ppa4_ptr && ppa4_ptr >= caddr_begin && ppa4_ptr < caddr_end &&
	  (type == TYPE_Function_LE_XPLINK || type == TYPE_Function_LE_CCN)) {
	if (ppa4_ptr[0] & 0x40) { /* do we have a source file name? */
	  if (ppa4_ptr[5] & 0x04) { /* 64 bit */
	    beginning_of_csect = ppa4_ptr + *(long *)(ppa4_ptr + 0x20);
	    end_of_csect = beginning_of_csect + *(long *)(ppa4_ptr + 0x28);
	    csect_name = ppa4_ptr + ppa4_ptr[7] + 4;
	  } else {
	    beginning_of_csect = ppa4_ptr + *(int *)(ppa4_ptr + 0x14);
	    end_of_csect = beginning_of_csect + *(int *)(ppa4_ptr + 0x18);
	    csect_name = ppa4_ptr + ppa4_ptr[7] + 4;
	  }
	  if (end_of_csect < (ppa2_ptr+0x18))
	    end_of_csect = (ppa2_ptr+0x18);
	  (*callback)(info, header, beginning_of_csect, end_of_csect, (char *)(csect_name+2), *(unsigned short *)csect_name, TYPE_Source);
	}
      }
      if (offset_to_name) {
	c_name_ptr = ppa1_ptr + offset_to_name;
      } else {
	type = 0;
	if (info_type != 0xF0) {
	  /*fprintf(out, "info=%02X\n", info_type);*/
	  /*fprint_buffer(out, ppa1_ptr, 0x30);*/
	}
      }
    }
    if (type) {
      if (prev_caddr && prev_c_name_ptr) {
	unsigned short name_length = *(unsigned short *)prev_c_name_ptr;
	char *name = (char *)prev_c_name_ptr + sizeof(unsigned short);
	result = (*callback)(info, header, prev_caddr, caddr, name, name_length, prev_type);
	if (result) return result;
      }
      prev_type = type;
      prev_caddr = caddr;
      prev_c_name_ptr = c_name_ptr;
      prev_ppa4_ptr = ppa4_ptr;
    }
  }
  return result;
}


void call_csvinfo(int function, void *ptr, void *info, call_csvinfo_callback *callback, char *caller)
{
  int result = 0;
  struct call_csvinfo *call = (struct call_csvinfo *)__malloc31(sizeof(struct call_csvinfo));
  memset(call, 0, sizeof(*call));
  call->csvinfo.version = 0;
  call->csvinfo.xflags1 = function | 0x04; /* ENV_MVS */
  if (function == 0x08)
    call->csvinfo.rb = ptr;
  else
    call->csvinfo.tcb = ptr;
  *(void * __ptr32 *)(call->csvinfo.userdata) = (void * __ptr32)(call->regs64_0);
  call->csvinfo_ptr = &call->csvinfo;
  int count = 0;
  while (1) {
    /* This is CSVINFO + the MODI callback */
    __asm("     LG   2,%2\n"       /* "m"(call) */
	  "     STMG 0,15,0(2)\n"
	  "     LA   1,%1\n"       /* "m"(call->csvinfo_ptr) */
	  "     LA   10,%0\n"      /* "=m"(call->r15_r0) */
	  "     LA   3,256(,2)\n"  /* offset to csvinfo, why not use reg 1? */
	  "     LG   4,136(,2)\n"  /* reg 1 in the second save area */
	  "     CHI  4,0\n"
	  "     BRC  7,R1_0\n"
	  "     SAM31\n"
	  "     LARL 4,MODI\n"
	  "     ST   4,16(,3)\n"
	  "     L    14,16(,0)\n"
	  "     L    14,140(,14)\n"
	  "     L    14,228(,14)\n"
	  "     L    15,20(,14) \n"
	  "     BALR 14,15\n"
	  "     STM  15,0,0(10)\n"
	  "     LHI  0,-1\n"
	  "     STG  0,136(,2)\n"
	  "     BRC  15,RTN\n"
	  "R1_0 LMG  0,15,128(2)\n" /* return from the callback */
	  "     SAM31\n"
	  "     LHI  15,0\n"
	  "     BR   14\n"
	  "MODI L    15,4(,1)\n"     /* the callback, R1=CSVMODI, R15=USERDATA */
	  "     STMG 0,15,128(15)\n"
	  "     LLGFR 2,15\n"
	  "RTN  SAM64\n"
	  "     LMG  0,15,0(2)\n"
	  : "=m"(call->r15_r0)
	  : "m"(call->csvinfo_ptr), "m"(call)
	  : "r2");
    int header_int = (int)*(long *)&(call->regs64_1[1]);
    struct modi_header * __ptr32 header = (struct modi_header * __ptr32)header_int;
    if (-1 == header_int)
      break;
    count += 1;
    result = (*callback)(info, header, NULL, NULL, NULL, 0, 0);
  }
  if (call->r15_r0.r15 != 0) {
    fprintf(stderr, "CSVINFO %s count=%d, R15=%X, R0=%X\n", caller, count, call->r15_r0.r15, call->r15_r0.r0);
    fflush(stderr);
  }
  free(call);
}

static unsigned char IBM_1047_to_ISO8859_1[256] = {
  0x00, 0x01, 0x02, 0x03, 0x9C, 0x09, 0x86, 0x7F, 0x97, 0x8D, 0x8E, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
  0x10, 0x11, 0x12, 0x13, 0x9D, 0x0A, 0x08, 0x87, 0x18, 0x19, 0x92, 0x8F, 0x1C, 0x1D, 0x1E, 0x1F,
  0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x17, 0x1B, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x05, 0x06, 0x07,
  0x90, 0x91, 0x16, 0x93, 0x94, 0x95, 0x96, 0x04, 0x98, 0x99, 0x9A, 0x9B, 0x14, 0x15, 0x9E, 0x1A,
  0x20, 0xA0, 0xE2, 0xE4, 0xE0, 0xE1, 0xE3, 0xE5, 0xE7, 0xF1, 0xA2, 0x2E, 0x3C, 0x28, 0x2B, 0x7C,
  0x26, 0xE9, 0xEA, 0xEB, 0xE8, 0xED, 0xEE, 0xEF, 0xEC, 0xDF, 0x21, 0x24, 0x2A, 0x29, 0x3B, 0x5E,
  0x2D, 0x2F, 0xC2, 0xC4, 0xC0, 0xC1, 0xC3, 0xC5, 0xC7, 0xD1, 0xA6, 0x2C, 0x25, 0x5F, 0x3E, 0x3F,
  0xF8, 0xC9, 0xCA, 0xCB, 0xC8, 0xCD, 0xCE, 0xCF, 0xCC, 0x60, 0x3A, 0x23, 0x40, 0x27, 0x3D, 0x22,
  0xD8, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0xAB, 0xBB, 0xF0, 0xFD, 0xFE, 0xB1,
  0xB0, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0xAA, 0xBA, 0xE6, 0xB8, 0xC6, 0xA4,
  0xB5, 0x7E, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0xA1, 0xBF, 0xD0, 0x5B, 0xDE, 0xAE,
  0xAC, 0xA3, 0xA5, 0xB7, 0xA9, 0xA7, 0xB6, 0xBC, 0xBD, 0xBE, 0xDD, 0xA8, 0xAF, 0x5D, 0xB4, 0xD7,
  0x7B, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0xAD, 0xF4, 0xF6, 0xF2, 0xF3, 0xF5,
  0x7D, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0xB9, 0xFB, 0xFC, 0xF9, 0xFA, 0xFF,
  0x5C, 0xF7, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0xB2, 0xD4, 0xD6, 0xD2, 0xD3, 0xD5,
  0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0xB3, 0xDB, 0xDC, 0xD9, 0xDA, 0x9F};

static void convert_buffer_to_local(char *buffer, int length)
{
  for (int i=0; i<length; i++) {
    buffer[i] = IBM_1047_to_ISO8859_1[(unsigned char)buffer[i]];
  }
}

static int name8_length(char *name)
{
  int length = 8;
  while (0x40 == name[length-1])
    length--;
  return length;
}

#include "Python.h"

struct python_info {
  PyObject *elements;
  PyObject *asid_obj;
  char name_buffer[512];
};

int call_callbacks(void *info_, void *addr_begin, void *addr_end, char *name, int type)
{
  struct python_info *info = (struct python_info *)info_;
  int level = 0;
  if (type == TYPE_Function_LE_Standard ||
      type == TYPE_Function_LE_Fastlink ||
      type == TYPE_Function_LE_CCN ||
      type == TYPE_Function_LE_XPLINK) {
    level = 5;
  } else if (type == TYPE_Source) {
    level = 4;
  } else if (type == TYPE_LoadPathname) {
    level = 1;
  } else if (type == TYPE_Load_major_and_minor) {
    level = 3;
  } else if (type == TYPE_Load) {
    level = 1;
  } else if (type == TYPE_Boundary) {
  }
  if (0 && (level > 3)) {
    fprintf(stdout, "%016lX %016lX %X %s\n", addr_begin, addr_end, level, name);
    fflush(stdout);
  }
  if (level) {
    PyObject *level_obj = PyLong_FromLong(level);
    PyObject *name_obj = PyUnicode_DecodeASCII(name, strlen(name), NULL);
    PyObject *tuple1 = Py_BuildValue("(OkiOO)", info->asid_obj, addr_begin, 1, level_obj, name_obj);
    PyObject *tuple0 = Py_BuildValue("(OkiOO)", info->asid_obj, addr_end,   0, level_obj, name_obj);
    PyList_Append(info->elements, tuple1);
    PyList_Append(info->elements, tuple0);
    Py_DECREF(tuple1);
    Py_DECREF(tuple0);
    Py_DECREF(level_obj);
    Py_DECREF(name_obj);
  }
  return 0;
}

int call_csvinfo_python_callback(void *info_, struct modi_header *header,
				 void *addr_begin, void *addr_end, char *name, int name_length, int type)
{
  struct python_info *info = (struct python_info *)info_;
  if (addr_begin == NULL) {
    if (header->modi_1_ptr->attr4 & MODI_PATHNAME) {
      type = TYPE_LoadPathname;
      name_length = header->modi_3_ptr->name_length;
      if (name_length > (sizeof(info->name_buffer) - 1)) name_length = sizeof(info->name_buffer) - 1;
      memcpy(info->name_buffer, header->modi_3_ptr->ep_name, name_length);
      convert_buffer_to_local(info->name_buffer, name_length);
      info->name_buffer[name_length] = 0;
      name = info->name_buffer; /* simplify_library_filename(info->name_buffer); */
      addr_begin = header->modi64_1_ptr->segment_address;
      addr_end = (unsigned char *)header->modi64_1_ptr->segment_address+header->modi64_1_ptr->segment_length;
    } else if (header->modi_1_ptr->attr2 & MODI_MINOR) {
      type = TYPE_Load_major_and_minor;
      char major[9], minor[9];
      memcpy(major, header->modi_5_ptr->major_name8, 8);
      convert_buffer_to_local(major, 8);
      major[name8_length(major)] = 0;
      memcpy(minor, header->modi_1_ptr->name8, 8);
      convert_buffer_to_local(minor, 8);
      minor[name8_length(minor)] = 0;
      snprintf(info->name_buffer, sizeof(info->name_buffer), "%s.%s", major, minor);
      name = info->name_buffer;
      addr_begin = (unsigned char *)((int)header->modi_1_ptr->ep & 0x7FFFFFFE);
      addr_end = (unsigned char *)header->modi64_1_ptr->segment_address+header->modi64_1_ptr->segment_length;
    } else {
      type = TYPE_Load;
      memcpy(info->name_buffer, header->modi_1_ptr->name8, 8);
      convert_buffer_to_local(info->name_buffer, 8);
      name_length = name8_length(info->name_buffer);
      info->name_buffer[name_length] = 0;
      name = info->name_buffer;
      addr_begin = header->modi64_1_ptr->segment_address;
      addr_end = (unsigned char *)header->modi64_1_ptr->segment_address+header->modi64_1_ptr->segment_length;
    }
  } else {
    if (name_length > (sizeof(info->name_buffer) - 1)) name_length = sizeof(info->name_buffer) - 1;
    memcpy(info->name_buffer, name, name_length);
    convert_buffer_to_local(info->name_buffer, name_length);
    info->name_buffer[name_length] = 0;
    if (type == 4)
      name = info->name_buffer; /* simplify_build_filename(info->name_buffer); */
    else
      name = info->name_buffer;
  }
  call_callbacks(info, addr_begin, addr_end, name, type);
  return 0;
}

#define MEM4(ptr,offset,name) *(char * __ptr32 * __ptr32)((char * __ptr32)(ptr)+offset)
#define MEM2(ptr,offset,name) *(unsigned short *)((char * __ptr32)(ptr)+offset)

PyDoc_STRVAR(get_csv_info__doc__,
	     "get_csv_info(elements, asid /)\n");

static PyObject *
get_csv_info(PyObject *module, PyObject *args)
{
  PyObject *elements;
  PyObject *asid_obj;
  if (!PyArg_ParseTuple(args, "OO:get_csv_info", &elements, &asid_obj)) {
    return NULL;
  }
  struct python_info info_s = {.elements = elements, .asid_obj = asid_obj, .name_buffer = {0}};
  struct python_info *info = &info_s;

  long asid = PyLong_AsLong(asid_obj);
  if (-1 == asid) {
    int ascb = (int)MEM4(0, 0x224, PSA_to_ASCB);
    unsigned short asid = MEM2(ascb, 0x24, ASCBASID); 
    int lda = (int)MEM4(ascb, 0x30, ASCB_to_LDA);
    unsigned int private24_low =  (unsigned int)MEM4(lda, 0x3C, STRTA);
    unsigned int private24_high = private24_low + (unsigned int)MEM4(lda, 0x40, SIZA);
    unsigned int private31_low =  (unsigned int)MEM4(lda, 0x4C, ESTRTA);
    unsigned int private31_high = private31_low + (unsigned int)MEM4(lda, 0x50, ESIZA);
    call_callbacks(info, (void *)0,              (void *)private24_low,  "common  ", TYPE_Boundary);
    call_callbacks(info, (void *)private24_low,  (void *)private24_high, "PRIVATE ", TYPE_Boundary);
    call_callbacks(info, (void *)private24_high, (void *)0x00FFFFFF,     "common  ", TYPE_Boundary);
    call_callbacks(info, (void *)0x01000000,     (void *)private31_low,  "common  ", TYPE_Boundary);
    call_callbacks(info, (void *)private31_low,  (void *)private31_high, "EPRV    ", TYPE_Boundary);
  } else if (0 == asid) {
    call_csvinfo(0x40, NULL, info, call_csvinfo_python_callback, "LPA"); /* LPA */
  } else {
    void *tcb = MEM4(0, 0x21C, PSATOLD); /* we should do all tasks */
    call_csvinfo(0x80, tcb, info, call_csvinfo_python_callback, "JPA"); /* JPA */
    call_csvinfo(0x20, tcb, info, call_csvinfo_python_callback, "TASKLOAD"); /* TASKLOAD */
    call_csvinfo(0x10, tcb, info, call_csvinfo_python_callback, "TASKALL"); /* TASKALL */
  }
  Py_RETURN_NONE;
}

int call_moduleinfo_python_callback(void *info_, struct modi_header *header,
				    void *addr_begin, void *addr_end, char *name, int name_length, int type)
{
  struct python_info *info = (struct python_info *)info_;
  if (name_length > (sizeof(info->name_buffer) - 1)) name_length = sizeof(info->name_buffer) - 1;
  memcpy(info->name_buffer, name, name_length);
  convert_buffer_to_local(info->name_buffer, name_length);
  info->name_buffer[name_length] = 0;
  call_callbacks(info, addr_begin, addr_end, info->name_buffer, type);
  return 0;
}

PyDoc_STRVAR(get_module_info__doc__,
	     "get_module_info(elements, asid, name, begin_address, end_address /)\n");

static PyObject *
get_module_info(PyObject *module, PyObject *args)
{
  PyObject *elements;
  PyObject *asid_obj;
  char *name;
  unsigned long begin_address;
  unsigned long end_address;
  if (!PyArg_ParseTuple(args, "OOsLL:get_module_info", &elements, &asid_obj, &name, &begin_address, &end_address)) {
    return NULL;
  }
  struct python_info info_s = {.elements = elements, .asid_obj = asid_obj, .name_buffer = {0}};
  if (0 != memcmp(name, "BB", 2)) {
    find_functions(call_moduleinfo_python_callback, &info_s, NULL,
		   (void *)begin_address, (long)end_address - (long)begin_address);
  }
  Py_RETURN_NONE;
}

static PyMethodDef _csv_info_methods[] = {
    {"get_csv_info", (PyCFunction)get_csv_info, METH_VARARGS, get_csv_info__doc__},
    {"get_module_info", (PyCFunction)get_module_info, METH_VARARGS, get_module_info__doc__},
    {NULL,              NULL}           /* sentinel */
};


static struct PyModuleDef _csv_info_module = {
    PyModuleDef_HEAD_INIT,
    "_csv_info",
    NULL,
    -1,
    _csv_info_methods,
    NULL,
    NULL,
    NULL,
    NULL
};

PyMODINIT_FUNC
PyInit__csv_info(void)
{
  PyObject *result = PyModule_Create(&_csv_info_module);
  return result;
}
