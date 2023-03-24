#include "rtti.h"

typedef struct InternalRTTIBaseClassDescriptor
{
    uintptr_t typeDescriptorAddress;
    DWORD numBases;
    PMD where;
    DWORD attributes;
} InternalRTTIBaseClassDescriptor;

typedef struct InternalRTTIClassHierarchyDescriptor
{
    DWORD signature;
    DWORD attributes;
    DWORD numBaseClasses;
    uintptr_t baseClassArrayAddress;
} InternalRTTIClassHierarchyDescriptor;

typedef struct InternalRTTICompleteObjectLocator
{
    DWORD signature;
    DWORD offset;
    DWORD cdOffset;
    uintptr_t typeDescriptorAddress;
    uintptr_t classDescriptorAddress;
} InternalRTTICompleteObjectLocator;

RTTIClassHierarchyDescriptor* readClassDescriptor(const Process* process, uintptr_t addr) {
    InternalRTTIClassHierarchyDescriptor internalDescriptor;
    ReadProcessMemory(process->handle, addr, &internalDescriptor, sizeof(InternalRTTIClassHierarchyDescriptor), 0);

    RTTIClassHierarchyDescriptor* descriptor = malloc(sizeof(RTTIClassHierarchyDescriptor));
    descriptor->signature = internalDescriptor.signature;
    descriptor->attributes = internalDescriptor.attributes;
    descriptor->numBaseClasses = internalDescriptor.numBaseClasses;
    descriptor->baseClassArray = calloc(descriptor->numBaseClasses, sizeof(RTTIBaseClassDescriptor));

    // Copy array of descriptor pointers
    uintptr_t* array = calloc(descriptor->numBaseClasses, sizeof(uintptr_t));
    ReadProcessMemory(process->handle, internalDescriptor.baseClassArrayAddress, array, sizeof(uintptr_t) * descriptor->numBaseClasses, 0);

    // Copy internal descriptors into array of normal descriptors
    for (int i = 0; i < descriptor->numBaseClasses; i++) {
        InternalRTTIBaseClassDescriptor internalDesc;
        ReadProcessMemory(process->handle, array[i], &internalDesc, sizeof(InternalRTTIBaseClassDescriptor), 0);

        RTTIBaseClassDescriptor* desc = &descriptor->baseClassArray[i];
        desc->numBases = internalDesc.numBases;
        desc->where = internalDesc.where;
        desc->attributes = internalDesc.attributes;

        ReadProcessMemory(process->handle, internalDesc.typeDescriptorAddress, &desc->typeDescriptor, sizeof(TypeDescriptor), 0);
    }

    free(array);

    return descriptor;
}

RTTICompleteObjectLocator* rtti_read_complete_object_locator(const Process* process, uintptr_t objAddress) {
    uintptr_t vftableAddress, colAddress;
    ReadProcessMemory(process->handle, objAddress, &vftableAddress, sizeof(uintptr_t), 0);
    ReadProcessMemory(process->handle, vftableAddress - sizeof(uintptr_t), &colAddress, sizeof(uintptr_t), 0);

    InternalRTTICompleteObjectLocator internalCol;
    ReadProcessMemory(process->handle, colAddress, &internalCol, sizeof(InternalRTTICompleteObjectLocator), 0);

    RTTICompleteObjectLocator* col = malloc(sizeof(RTTICompleteObjectLocator));
    col->signature = internalCol.signature;
    col->offset = internalCol.offset;
    col->cdOffset = internalCol.offset;
    col->typeDescriptor = malloc(sizeof(TypeDescriptor));
    ReadProcessMemory(process->handle, internalCol.typeDescriptorAddress, col->typeDescriptor, sizeof(TypeDescriptor), 0);
    col->classDescriptor = readClassDescriptor(process, internalCol.classDescriptorAddress);

    return col;
}

void rtti_free_complete_object_locator(RTTICompleteObjectLocator* col) {
    free(col->typeDescriptor);
    free(col->classDescriptor->baseClassArray);
    free(col->classDescriptor);
    free(col);
}