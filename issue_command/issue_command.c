#pragma comment (copyright, "(c) Copyright Rocket Software, Inc. 2014, 2019 All Rights Reserved.")

/*
(1)  You MUST ship with RACROUTE enabled security for this function
(2)  How do you establish a valid SAF USERID?
(3)  You should use REQUEST=TOKENBLD to establish an port of  for the MGCRE so that sites can use WHEN(CONSOLE) in OPERCMDS profiles
(4)  How are you setting the EMCS console name? How do you handle when name already in use in the sysplex?
(5)  You must issue SAF check for MVS.MCSOPER.consname in OPERCMDS before you activate your EMCS.
(6)  How are you going to treat late responses from operator commands?
*/

/*
c89 -c "-Wc,langlvl(extc99),gonum,goff,hgpr" -o issue_command.o ITOMSTC/src/issue_command.c
c89 "-Wl,ac=1" -o ~/bin/issue_command issue_command.o 
extattr +a ~/bin/issue_command

~/bin/issue_command -debug 1 -search 1 -command 'D EMCS,F,ST=L,CN=BJT*'
setenv CONSOLE_NAME RMH00001
setenv MAPPROCNAME BJTGTF
issue_command -timeout 5 -search 0 -console_name $CONSOLE_NAME -command "S ${MAPPROCNAME}.GTFMAP"
*/

/*
allocate the "struct console" objects in ECSA,
only when there is not one already available.
Have a root csa object, findable through name token.
use the first console that is not already in use.

add some reporting about the alert ecb.
*/

#pragma runopts(POSIX(ON))

#define _ALL_SOURCE
#define _POSIX_SOURCE
#define _OPEN_MSGQ_EXT

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <math.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/msg.h>
#include <unistd.h>
#include <builtins.h>

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif



void 
fprint_buffer(FILE *out, unsigned char *buffer, int length)
{
  int i;
  int index = 0;
  int last_index = length-1;
  int units = 4;

  char *charlist = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-_=~!#$%^&*()`[]\\{}|:;\"'<>?,./ ";
  char trans[256];

  for (i=0; i<256; i++) trans[i] = '.';
  for (i=0; 0 != charlist[i]; i++) trans[charlist[i]] = charlist[i];

  while (index <= last_index) {
    int pos;
    fprintf(out, "%08X %0.8X ",buffer+index,index);
    for (pos=0; pos<32; pos++) {
      if (0 < units && 0 == (index+pos)%units)
        fprintf(out, " ");
      if ((index+pos)<length)
        fprintf(out, "%0.2X",buffer[index+pos]);
      else
        fprintf(out, "  ");
    }
    fprintf(out, " |");
    for (pos=0; pos<32 && (index+pos)<length; pos++) {
      int ch = trans[buffer[index+pos]];
      fprintf(out, "%c", ch);
    }
    fprintf(out, "|\n");
    index += 32;
  }
  fflush(out);
}

void 
print_buffer(unsigned char *buffer, int length)
{
  fprint_buffer(stdout, buffer, length);
}


struct console;

/*** begin IEAVM105 ***/
struct mdb {
  short length; /* length of MDB and all following blocks */
  short type; /* MDB=1 */
  char id[4]; /* MDB  */
  unsigned int version; /* 1 */
};

struct mdb_general {
  short length;
  short type; /* MDBG=1 */

  unsigned char system_id;
  unsigned char sequence[3];
  char timestamp[11]; /* HH.MM.SS.TH */
  char reserved1;
  char date[7];
  char reserved2;
  short flags; /* DOM=0x8000, ALARM=0x4000, HOLD=0x2000 */
  char reserved3[2];
  unsigned char foreground_presentation[4];
  unsigned char background_presentation[4];
  char originating_system_name[8];
  char jobname[8];
};

struct mdb_control_program {
  short length;
  short type; /* 2 */
  unsigned char system_identifier[16];
  unsigned char routing_codes[16];
  unsigned char descriptor_codes[2];
  unsigned char message_level[2];
  unsigned char message_attributes[2];
#define MESSAGE_ATTRIBUTES1_IS_COMMAND_RESPONSE 0x40;
  unsigned char reserved1[4];
  unsigned short asid;
  unsigned char reserved2[0x54-0x30];
  unsigned char cart[8];
  unsigned char reserved3[0x100-0x5C];
};

struct mdb_text {
  short length;
  short type; /* 4 */
  unsigned char flags1; /* control=80,label=40,data=20,end=10,prompt=08 */
  unsigned char flags2;
  unsigned char presentation_attributes[4];
};
/*** end IEAVM105 ***/

struct r15_r0_r1_r2_fn_type {
  unsigned long r15;
  unsigned long r0;
  unsigned long r1;
  unsigned long r2;
  unsigned long fn;
  unsigned long type;
#define PRIM_TYPE_SVC 0
#define PRIM_TYPE_PC 1
#define PRIM_TYPE_SUP_PC 8
#define PRIM_TYPE_SUP_AR_PC 9
#define PRIM_TYPE_SUP_KEY0_SVC 10
  void *callback;
  void *save;
};

struct get_ar_memory {
  void *source;
  void *dest;
  int  source_length;
  int  dest_length;
  int  source_ar;
};

/*** begin IEZVG111 */
struct operparm {
  unsigned short message_data_space_size_in_mb;
  unsigned char authority_level; /* SYS, IO, and CONS can be mixed */
#define AUTHORITY_LEVEL_MASTER 0x80
#define AUTHORITY_LEVEL_ALL    0x40
#define AUTHORITY_LEVEL_SYS    0x20
#define AUTHORITY_LEVEL_IO     0x10
#define AUTHORITY_LEVEL_CONS   0x08
#define AUTHORITY_LEVEL_INFO   0x04 /* default */
  unsigned char reserved1;
  unsigned char operators_message_form;
#define OPERATORS_MESSAGE_FORM_TIME_STAMP  0x80  
#define OPERATORS_MESSAGE_FORM_SYSTEM_NAME 0x40 
#define OPERATORS_MESSAGE_FORM_JOB_ID_NAME 0x20 
#define OPERATORS_MESSAGE_FORM_NO_SYSTEM_TIME_OR_JOB 0x10 /* default */
#define OPERATORS_MESSAGE_FORM_NO_SYSTEM_OR_JOB 0x08
  unsigned char reserved2;
  unsigned char level[2];
  /*         EQU   X'80'         Receive WTORs */
  /*         EQU   X'40'         Receive IMMEDIATE ACTION messages */
  /*         EQU   X'20'         Receive CRITICAL EVENTUAL ACTION msgs */
  /*         EQU   X'10'         Receive EVENTUAL ACTION messages */
  /*         EQU   X'08'         Receive INFORMATIONAL messages */
  /*         EQU   X'04'         Receive BROADCAST messages           */
  /*         EQU   X'02'         Receive ALL message levels (DEFAULT) */
  /*         EQU   X'01'         Receive NO message levels            */
  unsigned char monitor[2];
  /*         EQU   X'80'         Monitor JOB NAMES */
  /*         EQU   X'40'         Monitor JOB NAMES, display w/time */
  /*         EQU   X'20'         Monitor SESSIONS */
  /*         EQU   X'10'         Monitor SESSIONS, display w/time */
  /*         EQU   X'08'         Monitor STATUS of freed data sets */
  unsigned char routing_code_flag;
#define ROUTING_CODE_ALL 0x80
#define ROUTING_CODE_NONE 0x40 /* default */
  unsigned char routing_codes[16];
  unsigned char log_command_response;
#define LOG_COMMAND_RESPONSE_SYSTEM 0x80 /* default */
#define LOG_COMMAND_RESPONSE_NO 0x40
  unsigned char reserved3;
  unsigned char receive_delete_operator_messages;
#define receive_delete_operator_messages_normal 0x80 /* default */
#define receive_delete_operator_messages_all 0x40
#define receive_delete_operator_messages_none 0x20
  char console_group_key[8];
  char command_system_name[8]; /* * means current system */
  char reserved4[8];
char scope_flags;
#define SCOPE_ALL 0x80 /* *ALL */
#define SCOPE_LIST 0x40
  char reserved5[1];
  void * __ptr32 scope_list; /* int number, char names[8][8]; */
  unsigned char misc_routing_flags;
#define MISC_ROUTING_FLAGS_QUEUE_AUTOMATABLE_MESSAGES_YES 0x20
#define MISC_ROUTING_FLAGS_QUEUE_AUTOMATABLE_MESSAGES_NO 0x10
#define MISC_ROUTING_FLAGS_RECEIVE_HARDCOPY_MESSAGE_SET_YES 0x08
#define MISC_ROUTING_FLAGS_RECEIVE_HARDCOPY_MESSAGE_SET_NO 0x04 /* default */
#define MISC_ROUTING_FLAGS_RECEIVE_CNID_0_MESSAGES_YES 0x02
#define MISC_ROUTING_FLAGS_RECEIVE_CNID_0_MESSAGES_NO 0x01 /* default */
  unsigned char security_flags;
#define SECURITY_FLAGS_OVERRIDE_YES 0x80
#define SECURITY_FLAGS_OVERRIDE_NO 0x40 /* default */
#define SECURITY_FLAGS_BYPASS_CONSNAME_CHECK_YES 0x08
#define SECURITY_FLAGS_BYPASS_CONSNAME_CHECK_NO 0x04 /* default */
  unsigned char misc_flags2;
#define MISC_FLAGS2_RECEIVE_MESSAGES_FROM_UNKNOWN_CNIDS_YES 0x80
#define MISC_FLAGS2_RECEIVE_MESSAGES_FROM_UNKNOWN_CNIDS_NO 0x40 /* default */
};
/*** end IEZVG111 */

struct console {
  char id[4];
  struct console *next;
  struct console *prev;
  struct operparm * __ptr32 operparm;
  unsigned int message_ecb;
  unsigned int alert_ecb;
  int consid;
  void * __ptr32 csa;
  unsigned int csa_alet;
  char consname[8];
  char termname[8];
  char userid[8];
  int activate_rc;   /* -1 means not active */
  int deactivate_rc; /* -1 means active */
};


char *get_arg(char *name, int argc, char **argv, int *i_ptr, char *line, int line_size);
struct console *console = 0;
struct console *create_console(char *consname, char *termname, struct operparm * __ptr32 operparm);
int activate_console(struct console *console);
int deactivate_console(struct console *console);
int free_console(struct console *console);
int issue_command(char *command, struct console *console, unsigned long long *command_stck);
struct mdb *retrieve_message(struct console *console, unsigned long long *command_stck, int *rc_ptr, int *reason_ptr);
int call_r15_r0_r1_r2_fn_type(struct r15_r0_r1_r2_fn_type *args);
void get_ar_memory(struct get_ar_memory *args);

#define MEM(ptr,offset,name) *(char * __ptr32 * __ptr32)((char * __ptr32)(ptr)+offset)
#define CSRT MEM(MEM(MEM(0,0x10,PSACVT),0x220,CVTCSRT),0x14,CSRTnametoken)
#define NT_CREATE_FN MEM(CSRT,0x4,CREATE)
#define NT_LOOKUP_FN MEM(CSRT,0x8,LOOKUP)
#define NT_DELETE_FN MEM(CSRT,0xC,DELETE)

unsigned short asid = 0;
int have_asid = FALSE;
int search = TRUE;
int receive_hardcopy_message_set = FALSE;
int debug = FALSE;
int print_headers = FALSE;
int trial_limit = 1;
char *consname = "BJT00001";
char *termname = "BJTCCMND";
char *command = 0;
double timeout = 1; /* seconds */
/*
issue_command -command [-|command] [-timeout timeout]
*/

void usage(void)
{
  printf("Usage: issue_command options\n");
  printf("  runs a command, and sends the output to stdout\n");
  printf("options:\n");
  printf("  -command command {this option is required}\n");
  printf("  -timeout {a positive floating point number, 1.0 is the default}\n");
  printf("  -print_headers 0|1 {if 1, SYSID, date, and time are printed on each line of stdout}\n");
  printf("  -console_name name {it is recommended that choose a name for this}\n");
  printf("  -asidx asid_in_hex\n");
  printf("  -search [0|1] {search for the messages using the command and response token,\n");
  printf("                 generated from STCK.  You should not need to specify this option.}\n");
  printf("If \"-\" is specified for any argument, a line is read from stdin, and used as the argument\n");
  printf("If the command is S or START, a line \"asidx=xxxx\" is written to stderr\n");
  printf("Do not specify -search for S, START, F MODIFY, or P STOP.\n");
  printf("Use -asidx for F MODIFY, or P STOP\n");
}

int main(int argc, char **argv)
{
  char *arg, *end;
  char line[64];
  int cpu_i = 0, time_i = 0;
  for (int i=1; i<argc; i++) {
    if (0!=(arg=get_arg("command", argc, argv, &i, line, sizeof(line)))) {
      command = strdup(arg);
      if (strlen(command)>126) {
        printf("command is too long\n");
        exit(1);
      }
      if (0 == strncmp(command, "S ", 2) || 0 == strncmp(command, "START ", 6)) {
        search = FALSE;
      }
    } else if (0!=(arg=get_arg("timeout", argc, argv, &i, line, sizeof(line)))) {
      timeout = strtod(arg, &end);
    } else if (0!=(arg=get_arg("debug", argc, argv, &i, line, sizeof(line)))) {
      debug = strtol(arg, &end, 10);
    } else if (0!=(arg=get_arg("search", argc, argv, &i, line, sizeof(line)))) {
      search = strtol(arg, &end, 10);
    } else if (0!=(arg=get_arg("asid", argc, argv, &i, line, sizeof(line)))) {
      asid = strtol(arg, &end, 10);
      have_asid = TRUE;
      search = FALSE;
    } else if (0!=(arg=get_arg("asidx", argc, argv, &i, line, sizeof(line)))) {
      asid = strtol(arg, &end, 16);
      have_asid = TRUE;
      search = FALSE;
    } else if (0!=(arg=get_arg("print_headers", argc, argv, &i, line, sizeof(line)))) {
      print_headers = strtol(arg, &end, 10);
    } else if (0!=(arg=get_arg("trial_limit", argc, argv, &i, line, sizeof(line)))) {
      trial_limit = strtol(arg, &end, 10);
    } else if (0!=(arg=get_arg("console_name", argc, argv, &i, line, sizeof(line)))) {
      consname = strdup(arg);
      if (strlen(consname)>8) {
        printf("console_name is too long\n");
        exit(1);
      }
    } else {
      printf("Invalid argument: %s\n", argv[i]);
      usage();
      exit(1);
    }
  }
  if (command == 0) {
    usage();
    exit(1);
  }
  int max_rc = 0;
  int max_rc_reason = 0;
  int max_rc_step = 0;
  int printed_header = FALSE;
  int rc, reason;
  struct mdb *mdb;
  struct operparm * __ptr32 operparm = (struct operparm * __ptr32)__malloc31(sizeof(struct operparm));
  memset(operparm, 0, sizeof(struct operparm));
  if (!search) operparm->misc_routing_flags |= MISC_ROUTING_FLAGS_RECEIVE_HARDCOPY_MESSAGE_SET_YES;
  struct console *console = create_console(consname, termname, operparm);
  rc = activate_console(console);
  if (rc) printf("activate_console rc=%d\n", rc);
  unsigned long long command_stck = 0;
  rc = issue_command(command,console,&command_stck);
  if (0 && rc) printf("issue_command rc=%d\n", rc);
  unsigned long long command_time = command_stck >> 12;
  unsigned long long end_time = command_time + (unsigned long long)(timeout * 1000000);
  char header[40];
  unsigned long long stck, current_time, wait_time, current_time_after_selectex, actual_wait_time;
  do {
    __stck(&stck);
    current_time = (stck >> 12);
    wait_time = (current_time > end_time) ? 0 : (end_time - current_time);
    if (debug) printf("before sleep, message ecb=%08X, wait_time=%.6f\n", console->message_ecb, ((double)wait_time)/1000000);
    struct timeval tv = {.tv_sec=(time_t)(wait_time/1000000), .tv_usec=(time_t)(wait_time%1000000)};
    selectex(0, 0, 0, 0, &tv, (int *)&console->message_ecb);
    __stck(&stck);
    current_time_after_selectex = (stck >> 12);
    actual_wait_time = current_time_after_selectex - current_time;
    if (debug) printf("after sleep, message ecb=%08X, actual wait time=%.6f\n", console->message_ecb, ((double)actual_wait_time)/1000000);
    console->message_ecb = 0;
    while (0!=(mdb=retrieve_message(console, &command_stck, &rc, &reason))) {
      unsigned char *mptr = (unsigned char *)(mdb+1);
      unsigned char *endptr = (unsigned char *)mdb + mdb->length;
      while (mptr < endptr) {
	unsigned short length = ((unsigned short *)mptr)[0];
	unsigned short type = ((unsigned short *)mptr)[1];
	if (debug) printf("mptr=%08X endptr=%08X length=%X type=%X\n", mptr, endptr, length, type);
	switch (type) {
	case 1: {
	  struct mdb_general *mdbg = (struct mdb_general *)mptr;
	  snprintf(header, sizeof(header), "%.8s %.7s %.11s  ",
		   mdbg->originating_system_name, mdbg->date, mdbg->timestamp);
	} break;
	case 2: {
	  struct mdb_control_program *mdbcp = (struct mdb_control_program *)mptr;
	  if (debug) print_buffer((unsigned char *)mdbcp, sizeof(*mdbcp));
	  if (have_asid) {
	    if (asid == mdbcp->asid) {
	      if (debug) printf("asid matches\n");
	    } else {
	      if (debug) printf("asid does not match\n");
	      mptr = endptr;
	    }
	  }
	} break;
	case 4: {
	  struct mdb_text *mdbt = (struct mdb_text *)mptr;
	  int text_length = mdbt->length-sizeof(struct mdb_text);
	  char *text = (char *)(mdbt+1);
          if (print_headers) printf("%s  ", header);
	  printf("%.*s\n", text_length, text);
	} break;
	}
	mptr += length;
      }
      fflush(stdout);
    }
    if (rc>8) {
      if (rc) printf("retrieve_message rc=%d\n", rc);
      break;
    }
  } while (wait_time > 0);
  rc = deactivate_console(console);
  if (rc) printf("deactivate_console rc=%d\n", rc);
  free_console(console);
}

char *get_arg(char *name, int argc, char **argv, int *i_ptr, char *line, int line_size)
{
  char *arg = argv[*i_ptr];
  if (arg[0]=='-' && 0==strcmp(arg+1,name)) {
    if ((1 + *i_ptr)>=argc) {
      printf("-%s must be followed by - or a %s\n",name,name);
      exit(1);
    }
    arg = argv[++*i_ptr];
    if (0==strcmp(arg,"-")) {
      char line[64];
      if (0!=fgets(line,line_size,stdin)) {
        char *nl = strchr(line,'\n');
        if (nl) *nl = 0;
        return line;
      } else {
        printf("Expected a %s in stdin\n",name);
        exit(1);
      }
    } else {
      return arg;
    }
  }
  return NULL;
}

struct mgcre { /* MGCRE TEXT=COMMAND,CONSID=CID,CART=CART */
  unsigned char flag1;
  unsigned char reserved1;
  unsigned char flag2; /* 0x84 MGCRE (0x80) + CONSID (0x04) */
  unsigned char flag3; /* 0x20 CART (0x20) */
  char id[5]; /* MGCRE */
  unsigned char version; /* 1 */
  unsigned char flag4;
  unsigned char reserved2;
  void * __ptr32 command;
  unsigned int token;
  char name[8];
  unsigned int consid; /* if CONSID is 0, the issuer receives MASTER command authority. */
  unsigned char command_disposition;
  unsigned char command_authority_level;
  unsigned char reserved3[2];
  unsigned char cart[8];
  char system_name[8];
  void * __ptr32 utoken;
  unsigned char reserved4[4];
  short command_len;
  char command_text[126];
};

int issue_command(char *command, struct console *console, unsigned long long *command_stck)
{
  struct mgcre *mgcre_call = (struct mgcre *)__malloc31(sizeof(struct mgcre));
  memset(mgcre_call, 0, sizeof(*mgcre_call));
  mgcre_call->flag2 = 0x84;
  mgcre_call->flag3 = 0x20;
  memcpy(mgcre_call->id, "MGCRE", 5);
  mgcre_call->version = 1;
  mgcre_call->consid = console ? console->consid : 0;
  mgcre_call->command = &mgcre_call->command_len;
  mgcre_call->command_len = strlen(command);
  strncpy(mgcre_call->command_text, command, sizeof(mgcre_call->command_text));
  __stck(command_stck);
  memcpy(mgcre_call->cart, command_stck, 8);
  if (debug) print_buffer((unsigned char *)mgcre_call, sizeof(*mgcre_call));
  struct r15_r0_r1_r2_fn_type mgcre_svc = {
    .r1=(unsigned int)mgcre_call, .fn=34 /* MGCRE */, .type=PRIM_TYPE_SUP_KEY0_SVC};
  call_r15_r0_r1_r2_fn_type(&mgcre_svc);
  if (debug) printf("MGCRE R15=%08X, R0=%08X, STCK=%016llX\n", mgcre_svc.r15, mgcre_svc.r0, *command_stck);
  int rc = mgcre_svc.r15;
  if (rc==0 && !have_asid) {
    asid = mgcre_svc.r0; have_asid = TRUE;
    fflush(stdout);
    fprintf(stderr, "asidx=%04X\n", asid);
    fflush(stderr);
  }
  free(mgcre_call);
  return rc;
}

/*  MCSOPER REQUEST=ACTIVATE,NAME=OPERNAME,CONSID=CID,TERMNAME=TERMNAME,  
    MSGDLVRY=SEARCH,MCSCSA=CSA,MCSCSAA=CSAALET,MSGECB=ECB */

struct mcse_csa {
  char id[4]; /* MCSC */
  unsigned char version; /* 1 */ 
  unsigned char flags; /* alert_post=0x80 */
  short reserved1;
  unsigned int consid; 
  unsigned int reserved2;
  /* some other fields */
};

/*
00000010 DS    F      Total Message Queue Depth
00000014 DS    F      Message Queue Depth for Unsolicited messages
00000018 DS    F      Message Queue Depth for Delivered (In Use) messages
0000001C DS    F      Maximum message queue depth permitted
00000020 DS    B      Message format - (Note: the bit offsets correspond to the UCMDISP2 field in the UCM)
EQU   X'80'  Display timestamp              
EQU   X'40'  Display jobname                
EQU   X'04'  Display system name            
EQU   X'02'  Don't display system name and jobname

The next four fields indicate the status of queuing at the time
when the ALERT ecb was posted.  The value one will be stored
into each field for which the following queuing condition
exists:
1. Memory Limit - no more cells in the data space. Queueing will be halted.
2. Queue Depth Limit - the console's message queue has reached the maximum depth.  Queueing will be halted.
3. Internal Error - an error occurred while manipulating the message queues.  Queueing will be halted.
4. Alert Percentage - the number of messages on the queue has reached a certain percentage of the maximum queue depth,
as defined by the ALERT percentage.  Queueing will continue.

The next field after these four will be used to request that the extended console be deactivated.  
The value one will be stored in the MCSCSUSP field.
5. Suspend Operator - the console is considered suspended by the system.  The extended console should be deactivated.
00000021 DS    X      Queuing Stopped by Memory Limit
00000022 DS    X      Queuing Stopped by Queue Depth Limit
00000023 DS    X      Queuing Stopped by Internal Error
00000024 DS    X      Queuing Reached Alert percentage 
00000025 DS    X      Request to suspend the operator  
00000026 DS    CL6    Reserved                         
0000002C DS    F      Flags field manipulated via Compare and Swap. Field will be initialized to zero when MCSCSA gets created in MCSOPER activation
00000030 ORG   MCSCFLGS_CS                              
0000002C DS    B      Byte 1                            
                               00000080             951+MCSCMESSAGEECBISPOSTED EQU  X'80'  A post was done on the Message ECB in EMCS queuer processing. It will be reset in cross memory Post Exit processing
00000030 DS    A      Pointer to O.C.O extension       
00000034 DS    0C     End of MCSCSA non-O.C.O portion  
*/

struct mcsoper {
  char id[4]; /* MCSO */
  unsigned char version; /* 1 */
  unsigned char request; /* ACTIVATE=1 DEACTIVATE=2 */
#define MCS_ACTIVATE 1
#define MCS_DEACTIVATE 2
  unsigned char flags; /* ABTIMER=YES, MIGID, MIGIDREL, NAME=0x10 */
  unsigned char reserved1;
  struct operparm * __ptr32 operparm;
  char name[8];
  char termname[8];
  unsigned int consid; /* out */
  unsigned int qlimit; /* 2147483647 */
  unsigned int csa_alet; /* out */
  void * __ptr32 csa; /* out */
  unsigned char reserved2[4];
  void * __ptr32 message_ecb;
  void * __ptr32 alert_ecb;
  unsigned char migid;
  unsigned char alert_pct; /* 100 */
  unsigned char qresume;
  unsigned char msgdlvry; /* FIFO=0x80 (default), SEARCH=0x40, NONE=0x20 */
  unsigned char reserved3[16];
};

int console_activate_or_deactivate(int request, struct console *console)
{
  struct mcsoper *mcsoper_call = (struct mcsoper *)__malloc31(sizeof(struct mcsoper));
  memset(mcsoper_call, 0, sizeof(mcsoper_call));
  memcpy(mcsoper_call->id, "MCSO", 4);
  mcsoper_call->version = 1;
  mcsoper_call->request = request;
  mcsoper_call->flags = (request==1) ? 0x10 /* NAME */ : 0;
  memcpy(mcsoper_call->name, console->consname, 8);
  memcpy(mcsoper_call->termname, console->termname, 8);
  mcsoper_call->qlimit = 2147483647;
  mcsoper_call->operparm = console->operparm;
  mcsoper_call->message_ecb = &console->message_ecb;
  mcsoper_call->alert_ecb = &console->alert_ecb;
  mcsoper_call->alert_pct = 100;
  mcsoper_call->msgdlvry = !search ? 0x80 /* FIFO */ : 0x40 /* SEARCH */;
  mcsoper_call->consid = console->consid;
  if (debug) print_buffer((unsigned char *)mcsoper_call,sizeof(*mcsoper_call));
  if (debug && request==MCS_ACTIVATE) print_buffer((unsigned char *)(console->operparm),sizeof(*(console->operparm)));
  unsigned int fn = (unsigned int)MEM(MEM(MEM(0,0x10,PSACVT),0x304,CVTSFT),0x64,MCSOPER)+1;
  struct r15_r0_r1_r2_fn_type mcsoper_pc = {
    .r1=(unsigned int)mcsoper_call, .fn=fn, .type=PRIM_TYPE_SUP_PC};
  call_r15_r0_r1_r2_fn_type(&mcsoper_pc);
  console->consid = mcsoper_call->consid;
  console->csa = mcsoper_call->csa;
  console->csa_alet = mcsoper_call->csa_alet;
  if (request == MCS_ACTIVATE) {
    console->activate_rc = mcsoper_pc.r15;
    console->deactivate_rc = -1;
  } else {
    console->activate_rc = -1;
    console->deactivate_rc = mcsoper_pc.r15;
  }
  if (debug || mcsoper_pc.r15)
    printf("MCSOPER R15=%08X, R0=%08X, CONSID=%08X, CSA=%08X, CSA_ALET=%08X\n", 
	   mcsoper_pc.r15, mcsoper_pc.r0, console->consid, console->csa, console->csa_alet);
  free(mcsoper_call);
  return (request == MCS_ACTIVATE) ? console->activate_rc : console->deactivate_rc;
}

struct console *create_console(char *consname, char *termname, struct operparm * __ptr32 operparm)
{
  struct console *console = (struct console *)__malloc31(sizeof(struct console));
  if (console == 0) return 0;
  memset(console, 0, sizeof(struct console));
  console->operparm = operparm;
  memset(console->consname, ' ', 8);
  memcpy(console->consname, consname, (strlen(consname)>8) ? 8 : strlen(consname));
  memset(console->termname, ' ', 8);
  memcpy(console->termname, termname, (strlen(termname)>8) ? 8 : strlen(termname));
  console->activate_rc = -1;
  console->deactivate_rc = -1;
  return console;
}

int activate_console(struct console *console)
{
  if (console == 0) return -1;
  console_activate_or_deactivate(MCS_ACTIVATE, console);
  return console->activate_rc;
}

int deactivate_console(struct console *console)
{
  if (console==0) return -1;
  int rc = 0;
  if (console->activate_rc > 4 || console->activate_rc < 0) {
    return -1;
  }
  console_activate_or_deactivate(MCS_DEACTIVATE, console);
  return console->deactivate_rc;
}

int free_console(struct console *console)
{
  int rc = deactivate_console(console);
  if (console==0) return -1;
  free(console);
  return rc;
}



/* requires supervisor state and ar mode */
struct mcsopmsg {
  char id[4]; /* MDR  */
  unsigned char version; /* 1 */
  unsigned char request; /* GETMSG=1, RESUME=2 */
  unsigned char flags; /* CMDRESP=YES = 0xA0, CART=0x10, MASK=0x08 */
  unsigned char reserved1;
  unsigned char cart[8];
  unsigned char mask[8];
  unsigned int consid;
  unsigned char reserved2[4];
};

struct mdb *retrieve_message(struct console *console, unsigned long long *command_stck, int *rc_ptr, int *reason_ptr)
{
  struct mcsopmsg *mcsopmsg_call = (struct mcsopmsg *)__malloc31(sizeof(struct mcsopmsg));
  memset(mcsopmsg_call, 0, sizeof(mcsopmsg_call));
  memcpy(mcsopmsg_call->id, "MDR ", 4);
  mcsopmsg_call->version = 1;
  mcsopmsg_call->request = 1;
  mcsopmsg_call->flags = search ? 0xB0 : 0;
  mcsopmsg_call->consid = console->consid;
  memcpy(mcsopmsg_call->cart, command_stck, 8);
  memset(mcsopmsg_call->mask, 0xFF, 8);
  if (debug) print_buffer((unsigned char *)mcsopmsg_call, sizeof(*mcsopmsg_call));
  int data_length = 0;
  void *data = 0;
  unsigned int fn = (unsigned int)MEM(MEM(MEM(0,0x10,PSACVT),0x304,CVTSFT),0x64,MCSOPER)+6;
  struct r15_r0_r1_r2_fn_type mcsopmsg_pc = {
    .r1=(unsigned int)mcsopmsg_call, .fn=fn, .type=PRIM_TYPE_SUP_AR_PC};
  call_r15_r0_r1_r2_fn_type(&mcsopmsg_pc);
  if (debug) printf("MCSOPMSG R15=%08X, R0=%08X, R1=%08X, R2=%08X\n", mcsopmsg_pc.r15, mcsopmsg_pc.r0, mcsopmsg_pc.r1, mcsopmsg_pc.r2);
  if (mcsopmsg_pc.r15 <= 4) {
    struct get_ar_memory getmem;
    unsigned short length = 0;
    getmem.source = (void *)mcsopmsg_pc.r1;
    getmem.source_ar = mcsopmsg_pc.r2;
    getmem.source_length = 2;
    getmem.dest = &length;
    getmem.dest_length = 2;
    if (debug) printf("retrieving length\n"); fflush(stdout);
    get_ar_memory(&getmem);
    if (debug) printf("length=%d\n", length); fflush(stdout);
    data = malloc(length);
    getmem.source_length = length;
    getmem.dest = data;
    getmem.dest_length = length;
    if (debug) printf("retrieving data\n"); fflush(stdout);
    get_ar_memory(&getmem);
  }
  *rc_ptr = mcsopmsg_pc.r15;
  *reason_ptr = mcsopmsg_pc.r0;
  return (struct mdb *)data;
}




static const unsigned short call_svc_code[] = {
#if __64BIT__
  0xEBEC, 0xD008, 0x0024,  /* STMG 14,12,8(13) */
  0xE370, 0x1000, 0x0004,  /* LG  R7,0(0,R1)    */
#else
  0x90EC, 0xD00C, /* STM 14,12,12(13) */
  0x5870, 0x1000, /* L   R7,0(0,R1)   */
#endif
  0x98F3, 0x7000, /* LM  R15,R3,0(R7) */
  0xC090, 0x0000, 0x0005, /* LARL R9,*+10 */
  0xA7F4, 0x0003, /* BRC X'F',*+6     */
  0x0A00,         /* SVC 0            */
  0x4430, 0x9000, /* EX  R3,0(0,R9)   */
  0x90F1, 0x7000, /* STM R15,R1,0(R7) */
#if __64BIT__
  0xEBEC, 0xD008, 0x0004, /* LMG 14,12,8(13) */
#else
  0x98EC, 0xD00C, /* LM 14,12,12(13)   */
#endif
  0x07FE};        /* BR 14             */

static const unsigned short call_sup_key0_svc_code[] = {
#if __64BIT__
  0xEBEC, 0xD008, 0x0024,  /* STMG 14,12,8(13) */
  0xE370, 0x1000, 0x0004,  /* LG  R7,0(0,R1)    */
#else
  0x90EC, 0xD00C, /* STM 14,12,12(13) */
  0x5870, 0x1000, /* L   R7,0(0,R1)   */
#endif
  0xA718, 0x003C, /* LHI R1,X'3C'     */   
  0x0A6B,         /* SVC X'6B'        */
  0x98F3, 0x7000, /* LM  R15,R3,0(R7) */
  0xC090, 0x0000, 0x0005, /* LARL R9,*+10 */
  0xA7F4, 0x0003, /* BRC X'F',*+6     */
  0x0A00,         /* SVC 0            */
  0x4430, 0x9000, /* EX  R3,0(0,R9)   */
  0x90F1, 0x7000, /* STM R15,R1,0(R7) */
  0xA718, 0x0024, /* LHI R1,X'24'     */   
  0x0A6B,         /* SVC X'6B'        */
#if __64BIT__
  0xEBEC, 0xD008, 0x0004, /* LMG 14,12,8(13) */
#else
  0x98EC, 0xD00C, /* LM 14,12,12(13)   */
#endif
  0x07FE};        /* BR 14             */

static const unsigned short call_pc_code[] = {
#if __64BIT__
  0xEBEC, 0xD008, 0x0024,  /* STMG 14,12,8(13) */
  0xE370, 0x1000, 0x0004,  /* LG  R7,0(0,R1)   */
#else
  0x90EC, 0xD00C, /* STM 14,12,12(13) */
  0x5870, 0x1000, /* L   R7,0(0,R1)   */
#endif
  0x98F3, 0x7000, /* LM  R15,R3,0(R7) */
  0x18E3,         /* LR  R14,R3       */
  0xB218, 0xE000, /* PC  0(R14)       */
  0x90F1, 0x7000, /* STM R15,R1,0(R7) */
#if __64BIT__
  0xEBEC, 0xD008, 0x0004, /* LMG 14,12,8(13) */
#else
  0x98EC, 0xD00C, /* LM 14,12,12(13)   */
#endif
  0x07FE};        /* BR 14            */

static const unsigned short call_sup_pc_code[] = {
#if __64BIT__
  0xEBEC, 0xD008, 0x0024,  /* STMG 14,12,8(13) */
  0xE370, 0x1000, 0x0004,  /* LG  R7,0(0,R1)   */
#else
  0x90EC, 0xD00C, /* STM 14,12,12(13) */
  0x5870, 0x1000, /* L   R7,0(0,R1)   */
#endif
  0xA718, 0x000C, /* LHI R1,X'0C'     */   
  0x0A6B,         /* SVC X'6B'        */
  0x98F3, 0x7000, /* LM  R15,R3,0(R7) */
  0x18E3,         /* LR  R14,R3       */
  0xB218, 0xE000, /* PC  0(R14)       */
  0x90F1, 0x7000, /* STM R15,R1,0(R7) */
  0xA718, 0x0004, /* LHI R1,X'04'     */   
  0x0A6B,         /* SVC X'6B'        */
#if __64BIT__
  0xEBEC, 0xD008, 0x0004, /* LMG 14,12,8(13) */
#else
  0x98EC, 0xD00C, /* LM 14,12,12(13)   */
#endif
  0x07FE};        /* BR 14            */

static const unsigned short call_sup_ar_pc_code[] = {
#if __64BIT__
  0xEBEC, 0xD008, 0x0024,  /* STMG 14,12,8(13) */
  0xE370, 0x1000, 0x0004,  /* LG  R7,0(0,R1)   */
#else
  0x90EC, 0xD00C, /* STM 14,12,12(13) */
  0x5870, 0x1000, /* L   R7,0(0,R1)   */
#endif
  0xA718, 0x000C, /* LHI R1,X'0C'     */   
  0x0A6B,         /* SVC X'6B'        */
  0x98F3, 0x7000, /* LM  R15,R3,0(R7) */
  0x18E3,         /* LR  R14,R3       */
  0x1788,         /* XR  R8,R8        */
  0xB24E, 0x0018, /* SAR R1,R8        */
  0xB219, 0x0200, /* SAC X'200'       */
  0xB218, 0xE000, /* PC  0(R14)       */
  0xB24F, 0x0021, /* EAR R2,R1        */
  0xB219, 0x0000, /* SAC X'000'       */
  0x90F2, 0x7000, /* STM R15,R2,0(R7) */
  0xA718, 0x0004, /* LHI R1,X'04'     */   
  0x0A6B,         /* SVC X'6B'        */
#if __64BIT__
  0xEBEC, 0xD008, 0x0004, /* LMG 14,12,8(13) */
#else
  0x98EC, 0xD00C, /* LM 14,12,12(13)   */
#endif
  0x07FE};        /* BR 14            */

typedef int call_fn(struct r15_r0_r1_r2_fn_type *args);
#pragma linkage(call_fn, OS)

int call_r15_r0_r1_r2_fn_type(struct r15_r0_r1_r2_fn_type *args)
{
  switch (args->type) {
  case PRIM_TYPE_SVC:
    return ((call_fn *)call_svc_code)(args);
  case PRIM_TYPE_PC: 
    return ((call_fn *)call_pc_code)(args);
  case PRIM_TYPE_SUP_PC:
    return ((call_fn *)call_sup_pc_code)(args);
  case PRIM_TYPE_SUP_AR_PC:
    return ((call_fn *)call_sup_ar_pc_code)(args);
  case PRIM_TYPE_SUP_KEY0_SVC:
    return ((call_fn *)call_sup_key0_svc_code)(args);
  default:
    return -1;
  }
}

int testauth(void)
{
  struct r15_r0_r1_r2_fn_type svc_args_s =
  {.r0=0xFFF00000, .r1=1, .fn=119 /* TESTAUTH */, .type=PRIM_TYPE_SVC};
  call_r15_r0_r1_r2_fn_type(&svc_args_s);
  return svc_args_s.r15;
}

static const unsigned short get_ar_memory_code[] = {
#if __64BIT__
  0xEBEC, 0xD008, 0x0024,  /* STMG 14,12,8(13) */
  0xE370, 0x1000, 0x0004,  /* LG  R7,0(0,R1)   */
  0xE320, 0x7000, 0x0004,  /* LG  R2,0(0,R7)   */
  0x5830, 0x7010,          /* L   R3,16(0,R7)  */
  0xE340, 0x7008, 0x0004,  /* LG  R4,8(0,R7)   */
  0x5850, 0x7014,          /* L   R5,20(0,R7)  */
  0x5860, 0x7018,          /* L   R6,24(0,R7)  */
#else
  0x90EC, 0xD00C, /* STM 14,12,12(13) */
  0x5870, 0x1000, /* L   R7,0(0,R1)   */
  0x5820, 0x7000, /* L   R2,0(0,R7)  */
  0x5830, 0x7008, /* L   R3,8(0,R7)  */
  0x5840, 0x7004, /* L   R4,4(0,R7)  */
  0x5850, 0x700C, /* L   R5,12(0,R7)  */
  0x5860, 0x7010, /* L   R6,16(0,R7)  */
#endif
  0xB24E, 0x0026, /* SAR R2,R6        */
  0xA718, 0x003C, /* LHI R1,X'3C'     */   
  0x0A6B,         /* SVC X'6B'        */
  0xB219, 0x0200, /* SAC X'200'       */
  0x0E42,         /* MVCL R4,R2       */
  0xB219, 0x0000, /* SAC X'000'       */
  0xA718, 0x0024, /* LHI R1,X'24'     */   
  0x0A6B,         /* SVC X'6B'        */
#if __64BIT__
  0xEBEC, 0xD008, 0x0004, /* LMG 14,12,8(13) */
#else
  0x98EC, 0xD00C, /* LM 14,12,12(13)   */
#endif
  0x07FE};        /* BR 14            */

typedef void get_ar_memory_fn(struct get_ar_memory *args);
#pragma linkage(get_ar_memory_fn, OS)

void get_ar_memory(struct get_ar_memory *args)
{
  ((get_ar_memory_fn *)get_ar_memory_code)(args);
}
