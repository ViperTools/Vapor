#pragma once
#include <windows.h>
#include "process.h"

typedef struct TypeDescriptor
{
    uintptr_t vftableAddress;
    uintptr_t spareAddress;
    const char name[2048]; // const char*
} TypeDescriptor;

typedef struct PMD
{
    int mdisp;
    int pdisp;
    int vdisp;
} PMD;

typedef struct InternalRTTIBaseClassDescriptor
{
    uintptr_t typeDescriptorAddress;
    DWORD numBases;
    PMD where;
    DWORD attributes;
} InternalRTTIBaseClassDescriptor;

typedef struct RTTIBaseClassDescriptor
{
    TypeDescriptor typeDescriptor; // TypeDescriptor
    DWORD numBases;
    PMD where;
    DWORD attributes;
} RTTIBaseClassDescriptor;

//typedef const struct RTTIBaseClassArray {
//    uintptr_t baseClassDescriptorsAddress; // RTTIBaseClassDescriptor[]
//} RTTIBaseClassArray;

typedef struct InternalRTTIClassHierarchyDescriptor
{
    DWORD signature;
    DWORD attributes;
    DWORD numBaseClasses;
    uintptr_t baseClassArrayAddress; // RTTIBaseClassArray
} InternalRTTIClassHierarchyDescriptor;

typedef struct RTTIClassHierarchyDescriptor
{
    DWORD signature;
    DWORD attributes;
    DWORD numBaseClasses;
    RTTIBaseClassDescriptor* baseClassArray; // RTTIBaseClassArray
} RTTIClassHierarchyDescriptor;

typedef struct InternalRTTICompleteObjectLocator
{
    DWORD signature;
    DWORD offset;
    DWORD cdOffset;
    uintptr_t typeDescriptorAddress; // TypeDescriptor
    uintptr_t classDescriptorAddress; // RTTIClassHierarchyDescriptor
} InternalRTTICompleteObjectLocator;

typedef struct RTTICompleteObjectLocator
{
    DWORD signature;
    DWORD offset;
    DWORD cdOffset;
    TypeDescriptor* typeDescriptor; // TypeDescriptor
    RTTIClassHierarchyDescriptor* classDescriptor; // RTTIClassHierarchyDescriptor
} RTTICompleteObjectLocator;

extern RTTICompleteObjectLocator* rtti_read_complete_object_locator(const Process* process, uintptr_t addr);
extern void rtti_free_complete_object_locator(RTTICompleteObjectLocator* col);