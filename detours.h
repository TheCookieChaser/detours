#pragma once
#include <Windows.h>
#include <iostream>
#include <cstdint>

class CDetourHook
{
public:
	CDetourHook(void* trampoline, void* hook_function)
	{
		m_original_function = trampoline;

		m_original_bytes = new std::uint8_t[6];
		m_hook_bytes = new std::uint8_t[6];

		if (!trampoline)
		{
			printf("[CDetourHook] Hooking attempted without trampoline\n");
			return;
		}

		if (!hook_function)
		{
			printf("[CDetourHook] Hooking attempted without hook function\n");
			return;
		}

		printf("[CDetourHook] Hooking function: 0x%p, new function: 0x%p\n", trampoline, hook_function);

		DWORD old_protect;
		if (!VirtualProtect(trampoline, 6, PAGE_EXECUTE_READWRITE, &old_protect))
		{
			printf("[CDetourHook] VirtualProtect failed, error code: 0x%lX\n", GetLastError());
			return;
		}

		memcpy(m_original_bytes, trampoline, 6);

		printf("[CDetourHook] Saving old instructions: [0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X]\n",
			m_original_bytes[0], m_original_bytes[1], m_original_bytes[2], m_original_bytes[3], m_original_bytes[4], m_original_bytes[5]);

		const auto rel_address = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(hook_function) - reinterpret_cast<std::uintptr_t>(trampoline) - 5);

		m_hook_bytes[0] = 0xE9; //jmp
		*reinterpret_cast<std::uint32_t*>(&m_hook_bytes[1]) = rel_address;
		m_hook_bytes[5] = 0xCC; //int3

		printf("[CDetourHook] Writing new instructions: [0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X]\n",
			m_hook_bytes[0], m_hook_bytes[1], m_hook_bytes[2], m_hook_bytes[3], m_hook_bytes[4], m_hook_bytes[5]);

		memcpy(trampoline, m_hook_bytes, 6);

		if (!VirtualProtect(trampoline, 6, old_protect, &old_protect))
		{
			printf("[CDetourHook] VirtualProtect failed, error code: 0x%lX\n", GetLastError());
			return;
		}
	}

	~CDetourHook()
	{
		unhook();
		delete[] m_original_bytes;
		delete[] m_hook_bytes;
	}

	void unhook() const
	{
		if (!m_original_function)
		{
			printf("[CDetourHook] unhook: original_function is nullptr\n");
			return;
		}

		if (!m_original_bytes)
		{
			printf("[CDetourHook] unhook: original_bytes is nullptr\n");
			return;
		}

		DWORD old_protect;
		if (!VirtualProtect(m_original_function, 6, PAGE_EXECUTE_READWRITE, &old_protect))
			printf("[CDetourHook] unhook: VirtualProtect failed, error code: 0x%lX\n", GetLastError());

		memcpy(m_original_function, m_original_bytes, 6);

		if (!VirtualProtect(m_original_function, 6, old_protect, &old_protect))
			printf("[CDetourHook] unhook: VirtualProtect failed, error code: 0x%lX\n", GetLastError());
	}

	void rehook() const
	{
		if (!m_original_function)
		{
			printf("[CDetourHook] rehook: original_function is nullptr\n");
			return;
		}

		if (!m_hook_bytes)
		{
			printf("[CDetourHook] rehook: hook_bytes is nullptr\n");
			return;
		}

		DWORD old_protect;
		if (!VirtualProtect(m_original_function, 6, PAGE_EXECUTE_READWRITE, &old_protect))
			printf("[CDetourHook] rehook: VirtualProtect failed, error code: 0x%lX\n", GetLastError());

		memcpy(m_original_function, m_hook_bytes, 6);

		if (!VirtualProtect(m_original_function, 6, old_protect, &old_protect))
			printf("[CDetourHook] rehook: VirtualProtect failed, error code: 0x%lX\n", GetLastError());
	}

	template<typename Fn = void*>
	Fn get_original_function()
	{
		return reinterpret_cast<Fn>(m_original_function);
	}

	template<typename ReturnType, typename Fn, typename... Args>
	ReturnType call_original(Args... args)
	{
		auto original = get_original_function<Fn>();
		if (!original)
			printf("[CDetourHook] call_original: original is nullptr\n");

		unhook();
		ReturnType ret = original(args...);
		rehook();

		return ret;
	}

	//template<typename Fn, typename... Args>
	//void call_original_noreturn(Args... args)
	//{
	//	auto original = get_original_function<Fn>();
	//	if (!original)
	//		printf("[CDetourHook] call_original_noreturn: original is nullptr\n");

	//	unhook();
	//	original(args...);
	//	rehook();
	//}

private:
	void* m_original_function = nullptr;
	std::uint8_t* m_original_bytes = nullptr;
	std::uint8_t* m_hook_bytes = nullptr;
};