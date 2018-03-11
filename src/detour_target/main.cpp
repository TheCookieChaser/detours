#include <windows.h>
#include <iostream>

int function(int a1, int a2, int a3)
{
	return (a1 + a2) * a3;
}

int main()
{
	while (true)
	{
		printf("(4 + 6) * 11 is %d\n", function(4, 6, 11));
		Sleep(1000);
	}

	getchar();
	return EXIT_SUCCESS;
}