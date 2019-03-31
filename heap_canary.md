�E�����_���ł͂Ȃ���ԂŌ��m�ł���悤�ɂ���B
�E�����_���ȏ�ԂŌ��m�ł���悤�ɂ���B
�Eheap head��p���āAheap_canary�̏ꏊ���ꔭ�Ō����ł���悤�ɂ���B
�Eheap_canary_list�̃t���O�����g���(�ȈՓI�ȃL���b�V���̎���)
	�L���b�V�����g�������̃L���b�V���\����Free�̃^�C�~���O
�E���͍s�����s��ꂽ�u�Ԃ�Check���邱�Ƃ͂ł��Ȃ����H(�΍􂪎v�����Ă��Ȃ�)

list_canary�\���̂��O���[�o���ɍ��B
struct list_canary{
	u32 index = 0   // heap_canary index
	u32 next  = 0   // next list
	u32 flag  = 0   // init:0, not yet:1
	u32 * list[256] // heap_canary_ptr
}

malloc(chk_malloc)��heap_canary(3byte+null)�쐬�Alist_canary�Ɋi�[
�Emalloc����Ƃ��ɁAheap_canary�̃T�C�Y�������Ĉ�Ԍ��ɑ������B
# define HEAP_CANARY_SIZE 4

static inline void* DFL_ck_alloc_nozero(u32 size){
	void* ret;
   u32 heap_canary = form_heap_canary();

	if (!size) return NULL;

	ALLOC_CHECK_SIZE(size);
	ret = malloc(size + ALLOC_OFF_HEAD + HEAP_CANARY_SIZE);
	ALLOC_CHECK_RESULT(ret, size);

	ret += ALLOC_OFF_HEAD; // offset
   
   ALLOC_C1(ret) = ALLOC_MAGIC_C1; // real_alloc(check_mem_corrrupt)
	ALLOC_S(ret)  = size;           // user_size
	ALLOC_C2(ret) = heap_canary;    // heap_canary
	store_heap_canary(heap_canary);

	return ret;

}

���̑��ADFL_ck_alloc_nozero�Ɠ����悤�Ȏ��������Ă���֐�
DFL_ck_realloc
DFL_ck_realloc_block
DFL_ck_strdup
DFL_ck_memdup
DFL_ck_memdup_str
DFL_ck_free


�Eform_heap_canary��heap_canary�𐶐�����B
static inline u32 form_heap_canary(){
   return rand() % 10000;
}

�E��������heap_canary��list�̋󂢂Ă���ꏊ�Ɋi�[����B
�Elist_canary��heap_canary�X�y�[�X���m�ہAstore_heap_canary���g����heap_canary���i�[
����:1 ���s:0
���s�����������񎎂��B
more�t���O��index��255�ɂȂ����Ƃ��ɁA�������list��NULL�����邩�m���߂�B���̂Ƃ��ANULL���Ȃ�������Alist�̐��𑝂₷�B�O��list�ɂ͌��݂̃\�[�X�ł͖߂�Ȃ�(�t���O�����g���)

static inline u32 store_heap_canary(u32 heap_canary){
	u32 * victim = 0;
   u32 more = 0;

	if(!list_s.flag){
		list_s.list[0] = (u32*)malloc(1024); // index 0~254
		memset(list_s.list[0], 0x0, 1024);
      list_s.flag = 1;
	}
	else if(list_s.index == 255){
		list_s.index = 0;
      if(!more){
         more++;
         goto list_loop;
      }
	}
	else if(list_s.next == 255){
		printf("list is full. sorry");
		return 0;
	}
list_loop:
	victim = list_s.list[list_s.next];
	while(list_s.index < 255){
		if(victim[list_s.index] == NULL){
			victim[list_s.index] = heap_canary;
			return 1;
		}
      list_s.index++;
	}
   if(more){
      list_s.index++;
		list_s.list[++list_s.next] = (u32*)malloc(1024); // index 0~254
		memset(list_s.list[list_s.next], 0x0, 1024);
      more = 0;
      goto list_loop;
   }

	return 0;
}

free(chk_free)��heap_canary��zero�ŏ���������B
�Echeck_heap_canary������B
#define ALLOC_C2(_ptr)  (((u32*)(_ptr))[ALLOC_S(_ptr) / 4]) // ��ԍŌ�̏ꏊ��heap_canary������B
free�����O��heap_ptr����heap_canary���i�[����Ă���ꏊ����肷��B
���肵��heap_canary��list�ɑ��݂��邩�A�m���߂�
overflow���Ă��Ȃ��̂ł���΁Aheap_canary��NULL�ɂ���B
overflow:0 not overflow:1
static inline u32 check_heap_canary(void* heap_ptr){
	u32 *heap_canary      = ALLOC_C2(heap_ptr);
	u32 victim_index      = 0;
	u32 victim_list_index = 0;
	u32 * victim          = list_s.list[0];

	while(victim_list_index < list_s.next + 1){
		while(victim_index < 255){
			if(victim[victim_index++] == heap_canary){
				printf("not overflow\n");
            victim[victim_index - 1 ] = NULL; //heap_ptr list canary is null
				return 1;
			}
		}
      if( victim = list_s.list[++victim_list_index] == NULL)
         break;
	}
	printf("overflow\n");
	return 0;
}

CHECK_PTR��check_heap_canary���s���B
#define CHECK_PTR(_p) do { \
    if (_p) { \
      if (ALLOC_C1(_p) ^ ALLOC_MAGIC_C1) {\
        if (ALLOC_C1(_p) == ALLOC_MAGIC_F) \
          ABORT("Use after free."); \
        else ABORT("Corrupted head alloc canary."); \
      } \
       if(!check_heap_canary(_p))                    \
         ABORT("Corrupted tail alloc canary."); \
    } \
  } while (0)


AFL�Ŏg����head����������B
�E�ŏ���1bit��1:use or 0:free, 7bit+1byte��index, 1byte��list_index
00 00 00 00
header����A���ꂼ��̗v�f�����o���B
#define HEAD_PTR(_ptr)  ALLOC_S(_ptr) >> 31        // use or free
#define IDX_PTR(_ptr) (ALLOC_S(_ptr) << 1) >> 21   // index
#define LIST_PTR(_ptr) (ALLOC_S(_ptr) << 12) >> 24 // list_index

header����A���ꂼ��̗v�f���i�[����B
#define USED_SET(_ptr) 
	(ALLOC_S(_ptr)  & (1 << 31))

#define FREED_SET(_ptr) (ALLOC_S(_ptr)  & (0 << 31))

#define IDX_SET(_ptr, index) (ALLOC_S(_ptr) & (0x7ff << 20)) \
	(ALLOC_S(_ptr)  ^ (index << 20))

#define LIST_SET(_ptr, list) (ALLOC_S(_ptr) & 0xff << 12) \
	(ALLOC_S(_ptr)  ^ (list << 12))
