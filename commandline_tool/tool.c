#include <stdio.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

void print_help() {printf("usage: ./pin -c core_to_pin path_to_command [args]\ne.g ./pin -c 0 /bin/echo 'Hello, World!'\n");}

int core = -1;
char **argv_;
int main(int argc, char *argv[]) {
	 if(argc < 2) { print_help(); return 0;}	
	 for(int i = 0; i < argc; i++) {
	 	if(!strcmp(argv[i], "-h")) { print_help(); return 0;}
		else if(!strcmp(argv[i], "-c")) { 
			core = atoi(argv[i + 1]); i += 2;
			printf("core: %d\n", core);
			argv_ = &argv[i];
			break;
		}
    }
	
	 int i = 0;
	 while(argv_[i] != 0) {
	 	printf("argv[%d]: %s\n", i, argv_[i]);
		i++;
	 }

    int ret = sysctlbyname("kern.pin_core", NULL, NULL, &core, sizeof(core));
    printf("ret: %d\n", ret);

    execve(argv_[0], argv_,  NULL);
}
