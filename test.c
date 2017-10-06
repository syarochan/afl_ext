#include "types.h"
#include "alloc-inl.h"

int main(){

   u32 * ptr1, ptr2, ptr3

   ptr1 = DFL_ck_alloc(0x50)
   ptr2 = DFL_ck_alloc(0x60)
   ptr3 = DFL_ck_alloc(0x70)

   DFL_ck_free(ptr1)
   DFL_ck_free(ptr2)
   DFL_ck_free(ptr3)
}
