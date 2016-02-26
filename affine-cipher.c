/* README */
/*
  This program implements a version of the famous 'affine cipher', the function it uses are
  cipher(plain_char) = ((plain_char * a) + b) mod 26
  decipher(cip_char) = ((cip_char - b)*(a^-1)) mod 26

  N.B. Due to mathematical reasons, this cipher only allows 312 different keys (one is the neutral key)
  so it's not kinda secure... It can be violated with a very simple brute force attack.

  For further informations or suggestions feel free to contact me on PasteBin : @DanFloyd
*/

/* LIBRARIES */
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

/* FUNCTIONS DEFINITION */
static void print_usage(); /* prints an help message */
static void failure(char* fail); /* prints an error message and exit */
static void cipher(FILE* msg, int k1, int k2); /* core cipher function */
static void decipher(FILE* msg, int k1, int k2); /* core decipher function */
static int mod_inv(int a, int b); /* calculates the modular inverse */

/* GLOBAL VARIABLES */
int log_f = 0;         /* log file flag */
FILE* log_file = NULL; /* log file */

/* MAIN FUNCTION */
int main (int argc, char** argv) {

  char o;                /* used for getopt */
  char tstamp[200];      /* used for create different titles for log files*/
  FILE *msg_file = NULL; /* message file */
  int dec_f = 0,         /* dechiper mode flag */
      K1,                /* first key */
      K2,                /* second key */
      offset;            /* offset for command line */

  /* searching options */
  while ((o = getopt(argc, argv, "dwh")) != -1) {
    switch (o) {
      case 'd' :
        dec_f = 1;
        break;
      case 'w' :
        log_f = 1;
        break;
      case 'h' :
        print_usage();
        exit(EXIT_SUCCESS);
      case '?' :
        failure("Unknown option. Please use option -h for help.");
        break;
    }
  }

  /* timestamp setting */
  sprintf(tstamp,"message-%u.txt",(unsigned) time(NULL));

  /* checking args number */
  if(argc < 4)
    failure("Missing arguments. Please use option -h for help.");

  /* setting offset for cmd line */
  switch(argc) {
    case 5 : {offset = 1;break;}
    case 6 : {offset = 2;break;}
    case 7 : {offset = 3;break;}
    default: {offset = 0;}
  }

  /* opening message's file */
  if((msg_file = fopen(argv[1+offset],"r")) == NULL){
    perror("Cannot open the file you specified.");
    failure("Fatal error.");
  }

  /* opening log file if requested */
  if(log_f){
    if((log_file = fopen(tstamp,"ab+")) == NULL){
      perror("Cannot open the log file.");
      failure("Fatal error.");
    }
  }

  /* setting keys */
  K1 = strtol(argv[2+offset], NULL, 10);
  if(errno == ERANGE || errno == EINVAL){
    failure("First key is too long or not in base 10.");
  }
  if(K1 < 1 || K1 == 13 || K1 > 25 || K1%2 == 0){
    failure("First key is not valid. Please use option -h for help.");
  }
  K2 = strtol(argv[3+offset], NULL, 10);
  if(errno == ERANGE || errno == EINVAL){
    failure("Second key is too long or not in base 10.");
  }
  K2 = K2%26;
  if(K1==1 && K2==0)
    fprintf(stderr, "[!!!] WARNING: You chose the neutral key combination, the message will not be ciphered.\n");

  /* chosing the mode */
  if(dec_f)
    decipher(msg_file, K1, K2);
  else
    cipher(msg_file, K1, K2);

  /* closing files */
  fclose(msg_file);
  if(log_f)
    fclose(log_file);

  return EXIT_SUCCESS;

}

/* FUNCTIONS IMPLEMENTATION */

static void failure(char* fail) {
  fprintf(stderr,"[!!!] ERROR: %s\n",fail);
  exit(EXIT_FAILURE);
}

static void print_usage() {
  fprintf(stderr,"Usage:\n");
  fprintf(stderr,"./acipher [FILE PATH] [KEY 1] [KEY 2] [OPTIONS]\n");
  fprintf(stderr,"Valid options are:\n");
  fprintf(stderr,"  -d : activate decipher mode\n");
  fprintf(stderr,"  -w : write a log file contains your ciphered/deciphered message\n");
  fprintf(stderr,"  -h : display this help message\n");
  fprintf(stderr,"Please note:\n");
  fprintf(stderr,"  - FILE PATH must be a valid path to a file that contains your message\n");
  fprintf(stderr,"  - KEY 1 must be an odd number between 1 and 12 or between 14 and 25\n");
}

static void cipher(FILE* msg, int k1, int k2){
  char ch, cip;
  while(fscanf(msg,"%c",&ch) != EOF){
    if(ch>=65 && ch <= 90){
      /* uppercase */
      cip = (((ch - 65)*k1)+k2)%26 + 65;
    } else if(ch>=97 && ch <= 122){
      /* lowercase */
      cip = (((ch - 97)*k1)+k2)%26 + 97;
    } else {
      /* space or other characters */
      cip = ch;
    }
    fprintf(stdout,"%c",cip);
    if(log_f)
      fprintf(log_file,"%c",cip);
  }
}

static void decipher(FILE* msg, int k1, int k2){
  int inv = mod_inv(k1,26);
  char ch, cip;
  while(fscanf(msg,"%c",&ch) != EOF){
    if(ch>=65 && ch <= 90){
      /* uppercase */
      cip = (((ch - 65)-k2)*inv + 26)%26 + 65;
    } else if(ch>=97 && ch <= 122){
      /* lowercase */
      cip = (((ch - 97)-k2)*inv + 26)%26 + 97;
    } else {
      /* space or other characters */
      cip = ch;
    }
    fprintf(stdout,"%c",cip);
    if(log_f)
      fprintf(log_file,"%c",cip);
  }
}

static int mod_inv(int n, int m){
  int x = 0;
  while(x<=m){
    if((n*x)%m == 1)
      return x;
    x++;
  }
  failure("Fatal error. Wrong key.");
  return EXIT_FAILURE;
}
