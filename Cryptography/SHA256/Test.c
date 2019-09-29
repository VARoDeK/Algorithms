#include <stdio.h>
#include <stdlib.h>
#include "sha256.h"

int main( int argc, char *argv[]){
  unsigned char *msg;
  if( argc == 1 ){
    msg = (unsigned char*)malloc( sizeof(unsigned char)* 1 );
    msg[0] = '\0';
  } 
  else
    msg = argv[1];

  calculate_sha256(msg);
  
  if(argc == 1)
    free( msg );

  printf("%s",sha256sum);
}