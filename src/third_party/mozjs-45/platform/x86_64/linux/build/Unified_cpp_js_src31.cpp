#define MOZ_UNIFIED_BUILD
#include "vm/PIC.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "vm/PIC.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "vm/PIC.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "vm/Printer.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "vm/Printer.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "vm/Printer.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "vm/Probes.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "vm/Probes.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "vm/Probes.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "vm/ProxyObject.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "vm/ProxyObject.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "vm/ProxyObject.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif
#include "vm/ReceiverGuard.cpp"
#ifdef PL_ARENA_CONST_ALIGN_MASK
#error "vm/ReceiverGuard.cpp uses PL_ARENA_CONST_ALIGN_MASK, so it cannot be built in unified mode."
#undef PL_ARENA_CONST_ALIGN_MASK
#endif
#ifdef INITGUID
#error "vm/ReceiverGuard.cpp defines INITGUID, so it cannot be built in unified mode."
#undef INITGUID
#endif