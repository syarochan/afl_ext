#include "types.h"
#include "alloc-inl.h"
#include <string.h>
int main(){

   u32 * ptr1, ptr2, ptr3;

   ptr1 = (u32*)DFL_ck_alloc(0x50);
   ptr2 = (u32*)DFL_ck_alloc(0x60);
   ptr3 = (u32*)DFL_ck_alloc(0x70);

   memset(ptr3, 'B', 0x71);
   
   DFL_ck_free(ptr1);
   DFL_ck_free(ptr2);
   DFL_ck_free(ptr3);
}
