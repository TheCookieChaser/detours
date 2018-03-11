#pragma once
#include <Windows.h>
#include <cstdint>

class cdetour_hook
{
public:
	cdetour_hook(void* trampoline, void* hook_function)
	{
		DWORD old_protect;
		VirtualProtect(trampoline, 6, PAGE_EXECUTE_READWRITE, &old_protect);

		m_original_function = trampoline;

		m_original_bytes = new std::uint8_t[6];
		m_hook_bytes = new std::uint8_t[6];

		memcpy(m_original_bytes, trampoline, 6);

		*reinterpret_cast<std::uint8_t*>(trampoline) = 0xE9;
		*reinterpret_cast<std::uint32_t*>(reinterpret_cast<std::uintptr_t>(trampoline) + 1)
			= reinterpret_cast<std::uintptr_t>(hook_function) - reinterpret_cast<std::uintptr_t>(trampoline) - 5;
		*reinterpret_cast<std::uint8_t*>(reinterpret_cast<std::uintptr_t>(trampoline) + 5) = 0xCC;

		memcpy(m_hook_bytes, trampoline, 6);

		VirtualProtect(trampoline, 6, old_protect, &old_protect);
	}

	~cdetour_hook()
	{
		unhook();
		delete[] m_original_bytes;
		delete[] m_hook_bytes;
	}

	void unhook()
	{
		DWORD old_protect;
		VirtualProtect(m_original_function, 6, PAGE_EXECUTE_READWRITE, &old_protect);

		memcpy(m_original_function, m_original_bytes, 6);

		VirtualProtect(m_original_function, 6, old_protect, &old_protect);
	}

	void rehook()
	{
		DWORD old_protect;
		VirtualProtect(m_original_function, 6, PAGE_EXECUTE_READWRITE, &old_protect);

		memcpy(m_original_function, m_hook_bytes, 6);

		VirtualProtect(m_original_function, 6, old_protect, &old_protect);
	}

	template<typename fn = void*>
	fn get_original_function()
	{
		return reinterpret_cast<fn>(m_original_function);
	}

private:
	void* m_original_function = nullptr;
	std::uint8_t* m_original_bytes;
	std::uint8_t* m_hook_bytes;
};