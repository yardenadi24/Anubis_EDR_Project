#pragma once
#include <ntifs.h>

#define POOL_TAG EDR_MEMORY_TAG

#include "commons.h"

#pragma warning(disable: 4996)

////////////////////////// -------- Allocation Operators -------- //////////////////////////
// Placement new operator
// Example:	new (Address) Type(Args...)
VOID* __cdecl operator new (size_t, VOID* P)
{
	return P;
}

VOID* __cdecl operator new[](size_t, VOID* P)
{
	return P;
}

// Allocation new operator
// Example: new Type(Args...)
VOID* __cdecl operator new (size_t Size, POOL_TYPE PoolType)
{
	VOID* P = NULL;
	if (Size == 0)
	{
		DbgError("Allocation with size 0");
		return NULL;
	}

	P = ExAllocatePoolWithTag(PoolType, Size, POOL_TAG);
	if (P == NULL)
	{
		DbgError("Failed to allocate memory, size: %zu", Size);
		return NULL;
	}

	RtlZeroMemory(P, Size);
	return P;
}


VOID* __cdecl operator new[](size_t Size, POOL_TYPE PoolType)
{
	VOID* P = NULL;
	if (Size == 0)
	{
		DbgError("Allocation with size 0");
		return NULL;
	}

	P = ExAllocatePoolWithTag(PoolType, Size, POOL_TAG);
	if (P == NULL)
	{
		DbgError("Failed to allocate memory, size: %zu", Size);
		return NULL;
	}

	RtlZeroMemory(P, Size);
	return P;
}

// Placement delete operator
VOID __cdecl operator delete (VOID*, VOID*) {}
VOID __cdecl operator delete[](VOID*, VOID*) {}

// delete operator
VOID __cdecl operator delete (VOID* P)
{
	if (P == NULL)
	{
		DbgError("Delete with NULL pointer");
		return;
	}

	ExFreePool(P);
}

////////////////////////// -------- KSynchronization -------- //////////////////////////

// Fast mutex //
class FastMutex
{

private:
	FAST_MUTEX m_FastMutex;
	BOOLEAN m_isLocked = FALSE;
public:
	FastMutex()
	{
		ExInitializeFastMutex(&m_FastMutex);
	}

	_IRQL_requires_max_(APC_LEVEL)
	_IRQL_raises_(APC_LEVEL)
	VOID Lock()
	{
		ExAcquireFastMutex(&m_FastMutex);
		m_isLocked = TRUE;
	}

	_IRQL_requires_max_(APC_LEVEL)
	VOID Unlock()
	{
		ExReleaseFastMutex(&m_FastMutex);
		m_isLocked = FALSE;
	}

	~FastMutex()
	{
		if(m_isLocked)
			Unlock();
	}
};


// Spin lock //
class SpinLock
{
private:
	KSPIN_LOCK m_SpinLock;
	KIRQL OldIrql = NULL;
	BOOLEAN m_isLocked = FALSE;
public:
	SpinLock()
	{
		KeInitializeSpinLock(&m_SpinLock);
	}

	VOID Lock()
	{
		KeAcquireSpinLock(&m_SpinLock, &OldIrql);
		m_isLocked = TRUE;
	}

	VOID Unlock()
	{
		KeReleaseSpinLock(&m_SpinLock, OldIrql);
		m_isLocked = FALSE;
	}

	~SpinLock()
	{
		if(m_isLocked)
			Unlock();
	}
};

//////////////////////////// -------- Atomic Operators -------- //////////////////////////

///////////////////////////  -------- List -------- //////////////////////////

template<typename Data>
class List
{
private:
	LIST_ENTRY m_Head = {};
	size_t m_Size = 0;
	FastMutex m_Lock;

public:
	// Internal element
	struct ListElement
	{
		LIST_ENTRY ListEntry = {};
		Data m_Data;

		ListElement() = default;
		ListElement(const Data& Data) : m_Data(Data) {};
	};

	// Get Element out of LIST_ENTRY
	static ListElement* GetElementUnSafe(LIST_ENTRY* pListEntry)
	{
		if (pListEntry == NULL)
		{
			DbgError("GetElement: pListEntry is NULL");
			return NULL;
		}
		return CONTAINING_RECORD(pListEntry, ListElement, ListEntry);
	}

	// Add this method to resolve the reference
	static ListElement* GetElement(LIST_ENTRY* pListEntry) {
		return GetElementUnSafe(pListEntry);
	}

	List()
	{
		InitializeListHead(&m_Head);
	}

	~List()
	{
		Clear();
	}
	
	// No copy options
	List(const List&) = delete;
	List& operator=(const List&) = delete;

	VOID Clear()
	{
		PLIST_ENTRY pHead = &m_Head;
		m_Lock.Lock();
		while (!IsListEmpty(pHead))
		{
			// Free list element
			PLIST_ENTRY pEntry = RemoveHeadList(pHead);
			ListElement* pElement = GetElementUnSafe(pEntry);
			if (pElement)
			{
				ExFreePool(pElement);
			}
		}
		m_Size = 0;
		InitializeListHead(pHead);
		m_Lock.Unlock();
		// Reset list head
	}

	NTSTATUS Add(Data Data)
	{
		ListElement* pElement = new (NonPagedPool) ListElement(Data);

		if (pElement == NULL)
		{
			DbgError("Add: pElement is NULL");
			return STATUS_INVALID_PARAMETER;
		}
		m_Lock.Lock();
		InsertHeadList(&m_Head, &pElement->ListEntry);
		m_Size++;
		m_Lock.Unlock();
		return STATUS_SUCCESS;
	}

	NTSTATUS Remove(Data Data)
	{
		m_Lock.Lock();
		if (IsEmpty())
		{
			DbgError("Remove: List is empty");
			m_Lock.Unlock();
			return STATUS_UNSUCCESSFUL;
		}

		// Search for the element
		ListElement* pElement = FindUnSafe(Data);

		if (pElement == NULL)
		{
			m_Lock.Unlock();
			DbgError("Remove: Element not found");
			return STATUS_NOT_FOUND;
		}

		RemoveEntryList(&pElement->ListEntry);

		// Free the element
		ExFreePool(pElement);
		m_Size--;
		m_Lock.Unlock();
		return STATUS_SUCCESS;
	}

	ListElement* FindUnSafe(Data Data)
	{
		if (IsEmpty())
		{
			DbgError("Find: List is empty");
			return NULL;
		}

		PLIST_ENTRY pHead = &m_Head;
		for (PLIST_ENTRY pEntry = pHead->Flink; pEntry != pHead; pEntry = pEntry->Flink)
		{
			ListElement* pElement = GetElementUnSafe(pEntry);
			if (pElement && pElement->m_Data == Data)
			{
				return pElement;
			}
		}
		return NULL;
	}

	BOOLEAN Exists(Data Data)
	{
		m_Lock.Lock();
		ListElement* pElement = FindUnSafe(Data);
		m_Lock.Unlock();
		return (pElement != NULL);
	}

	BOOLEAN IsEmpty()
	{
		return IsListEmpty(&m_Head);
	}

	size_t Size()
	{
		return m_Size;
	}


};