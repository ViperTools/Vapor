#pragma once
#include <windows.h>
#include "process.h"

typedef struct TypeDescriptor
{
    uintptr_t vftableAddress;
    uintptr_t spareAddress;
    char name[2048];
} TypeDescriptor;

typedef struct PMD
{
    int mdisp;
    int pdisp;
    int vdisp;
} PMD;

typedef struct RTTIBaseClassDescriptor
{
    TypeDescriptor typeDescriptor; // TypeDescriptor
    DWORD numBases;
    PMD where;
    DWORD attributes;
} RTTIBaseClassDescriptor;

typedef struct RTTIClassHierarchyDescriptor
{
    DWORD signature;
    DWORD attributes;
    DWORD numBaseClasses;
    RTTIBaseClassDescriptor* baseClassArray; // RTTIBaseClassArray
} RTTIClassHierarchyDescriptor;

typedef struct RTTICompleteObjectLocator
{
    DWORD signature;
    DWORD offset;
    DWORD cdOffset;
    TypeDescriptor* typeDescriptor; // TypeDescriptor
    RTTIClassHierarchyDescriptor* classDescriptor; // RTTIClassHierarchyDescriptor
} RTTICompleteObjectLocator;

extern RTTICompleteObjectLocator* rtti_read_complete_object_locator(const Process* process, uintptr_t objAddress);
extern void rtti_free_complete_object_locator(RTTICompleteObjectLocator* col);