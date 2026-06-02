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
**Read the full technical breakdown on how this manual mapping engine and stealth cleanup works:** [Reflective DLL Injection](https://arth.imbeddex.com/malware/development/Reflective%20DLL%20Injection)
# Demo
![Reflective Loader Demo](demo.gif)
## Overview

Hi, so YARL is a stealthy reflective injector, with a manual mapping engine and a driver under the hood.
YARL downloads your .dll from your server and injects and maps it to another process :)
and calls its dllmain in a new thread and the driver hides all the VAD entries for the manully mapped dll.

## Disclaimer
**This tool is for educational purposes and authorized red teaming simulations only.**
The author is not responsible for any misuse of this software. Do not use this tool on systems you do not have explicit permission to test.

## How YARL works
### 0x1 Loader ->
```markdown
> 1) YARL downloads a .dll from a remote server, using custom networking functions,
>      straight into a vector, so nothing ever touches the disk
> 2) The data of this vector it passed to the injector (injection.cpp)
> 3) The injector maps the Headers and sections in the target.
> 4) The injected shellcode further manually maps the dll from inside the target.
> 5) Once the mapping is done, the shellcode asks the driver to hide the injected dll.
> 6) VAD entries for the injected dll are unlinked.
```
### 0x2 Shellcode ->
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
> 5) Communicates with the driver
```


### 0x3 The Driver ->
The driver is also manually mapped, the mpping process and the code for the driver will not be shared publicly for security reasons.
Once loaded the driver does the following stuff:
```markdown
> 1) Creates a fake driver object.
> 2) Creates a Device.
> 3) Creates a symbolic link.
> 4) Does some driver signature enforcement bypass.
> 5) Subscribes to SetCreateProcessNotifyRoutineEx.
> 6) waits for the shellcode.
```

Once the shellcode asks the driver to hide the manually mapped dll the driver:
```markdown
> 1) Switches its context to the target process. 
> 2) Finds the VAD entries.
> 3) Unlinks and stores the entries.
> 4) Intercepts the target process termination.
> 5) Re-attaches the removed entries.
> 6) Lets the process terminate in order not to cause any BSOD.
```

### 0x4 Results ->

Everything is tested on Windows 11 25H2:
```markdown
> Antimalware Client Version: 4.18.25110.6
> Engine Version: 1.1.25110.1
> Antivirus Version: 1.443.854.0
> Antispyware Version: 1.443.854.0
```

Memory forensics is done using:
```markdown
> pe-sieve (v0.4.1.1)
> Moneta (v1.0)
> hollows_hunter (v0.4.1.1)
```


## Usage
Implimenting it in your code requires you to have its header, driver, networking libraries, and some more dlls which are not provided here..
>This is done in order to stop any noobie from messing up and exposing its static and dynamic signatures

But..

for those who are not noobies, you can find some of the required resources on my GitHub scattered around :)
>Will require a lil bit figuring things out tho..

## The End
So people have fun stay safe, If you have further ideas go on I am all ears.

