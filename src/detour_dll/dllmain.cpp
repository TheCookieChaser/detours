#include "detour.h"
#include <psapi.h>
#include <utility>
#include <array>
#include <algorithm>
#include <vector>

cdetour_hook* function1;

auto find_pattern(const char* module_name, const char* pattern, const char* mask) -> std::uintptr_t
{
	MODULEINFO module_info = {};
	K32GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(module_name), &module_info, sizeof(MODULEINFO));
	const auto address = reinterpret_cast<std::uint8_t*>(module_info.lpBaseOfDll);
	const auto size = module_info.SizeOfImage;
	std::vector<std::pair<std::uint8_t, bool>> signature;
	for (auto i = 0u; mask[i]; i++)
		signature.push_back(std::make_pair(pattern[i], mask[i] == 'x'));
	auto ret = std::search(address, address + size, signature.begin(), signature.end(),
		[](std::uint8_t curr, std::pair<std::uint8_t, bool> curr_pattern)
	{
		return (!curr_pattern.second) || curr == curr_pattern.first;
	});
	return ret == address + size ? 0 : std::uintptr_t(ret);
}

int function_hooked(int a1, int a2, int a3)
{
	static auto original = function1->get_original_function<decltype(&function_hooked)>();

	function1->unhook();
	auto original_function_value = original(a1, a2, a3);
	function1->rehook();

	printf("original value: %d\n", original_function_value);

	return 69;
}

DWORD WINAPI thread(LPVOID dll)
{
	auto function = find_pattern("detour_target.exe",
		"\x55\x8B\xEC\x81\xEC\x00\x00\x00\x00\x53\x56\x57\x8D\xBD\x00\x00\x00\x00\xB9\x00\x00\x00\x00\xB8\x00\x00\x00\x00\xF3\xAB\x8B\x45\x08",
		"xxxxx????xxxxx????x????x????xxxxx");
	printf("function: 0x%X\n", function);

	function1 = new cdetour_hook(reinterpret_cast<void*>(function), reinterpret_cast<void*>(function_hooked));

	FreeLibraryAndExitThread(static_cast<HMODULE>(dll), EXIT_SUCCESS);
}

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
		CreateThread(nullptr, 0, thread, hinstDLL, 0, nullptr);

	return TRUE;
}