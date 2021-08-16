#include <binscan.h>


int main()
{
	binscan_t* binscan = binscan_new();
	if (!binscan_openfile(binscan, "examples/example1.txt")) {
		return EXIT_FAILURE;
	}

	if (!binscan_register(binscan, 0, "48 65 6C ?? 6F")) {
		return EXIT_FAILURE;
	}
	if (!binscan_register(binscan, 0, "?? ?? 69 72 6B 73")) {
		return EXIT_FAILURE;
	}
	if (!binscan_register(binscan, 0, "77 ?? 69 72 64")) {
		return EXIT_FAILURE;
	}
	if (!binscan_register(binscan, 0, "FF 74 73")) {
		return EXIT_FAILURE;
	}

	int num_matches = binscan_exec(binscan);
	printf("Num matches: %d\n", num_matches);

	/*
	binscan_match_t* match = binscan_next(binscan);
	while (match) {
		printf("\tMatch: s='%s', uid='%d', addr='%p'\n", match->signature, match->uid, (void*)match->addr); 
		match = binscan_next(binscan);
	}
	*/

	binscan_delete(binscan);	
	return 0;
}
