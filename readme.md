# YetAnotherReflectiveLoader
> By **Oorth**
<pre align="center">

▓██   ██▓ ▄▄▄       ██▀███   ██▓    
 ▒██  ██▒▒████▄    ▓██ ▒ ██▒▓██▒    
  ▒██ ██░▒██  ▀█▄  ▓██ ░▄█ ▒▒██░    
  ░ ▐██▓░░██▄▄▄▄██ ▒██▀▀█▄  ▒██░    
  ░ ██▒▓░ ▓█   ▓██▒░██▓ ▒██▒░██████▒
   ██▒▒▒  ▒▒   ▓▒█░░ ▒▓ ░▒▓░░ ▒░▓  ░
 ▓██ ░▒░   ▒   ▒▒ ░  ░▒ ░ ▒░░ ░ ▒  ░
 ▒ ▒ ░░    ░   ▒     ░░   ░   ░ ░   
 ░ ░           ░  ░   ░         ░  ░
 ░ ░                                

</pre>

## Overview

Hi, so YARL is a stealthy refelctive injector, with a manual mapping engine under the hood.
YARL downloads your .dll from your server and injects and maps it to another process :)
and calls its dllmain in a new thread (if it has one..)
>~~So all ur doings look like someone else's ;)~~

## How YARL works
### Loader ->
```markdown
> 1) YARL downloads a .dll from a remote server, using custom networking functions,
>      straight into a vector, so nothing ever touches the disk
> 2) The data of this vector it passed to the injector (injection.cpp)
> 3) The injector maps the Headers and sections in the target
> 4) Injects the resources(for the shellcoee) and the shellcode in the target too
```
### Shellcode ->
The Shellcode is a very intresting piece of code.. It is position independent, and has to work with 0 resources
as windows has no clue that it exists, nor it can use C runtime functions as environment is not initilised.
It can only do pure C pointer arithmetics.

The shellcode is stored in ".stub" section inside the loader PE
the .stub section contains the shellcode as well as minimal and pure 'C' helper functions 
The loader, in order to help the shellcode places the helper functions and a structure above the shellcode
```markdown
    struct _RESOURCES
    {
        BYTE* Injected_dll_base;
        BYTE* ResourceBase;
        BYTE* Injected_Shellcode_base;
    }sResources_for_shellcode;
```

The shellcode then walks the target's PEB to find loaded libraries and functions and uses them when required..
shellcode then
```markdown
> 1) Performs the relocations
> 2) Tls Callbacks
> 3) Import Resolutions
> 4) Creates a new thread and calls the DllMain
```

## Usage
Implimenting it in your code requires you to have its header, networking libraries, and some more dlls which are not provided here..
>This is done in order to stop any noobie from using and exposing its static and dynamic signatures

But..

for those who are not noobies, you can find all the required resources on my GitHub scattered around :)
>Will require a lil bit figuring things out tho..

## The End
So people have fun stay safe, If you have further ideas go on I am all ears.

