# MacOS_CoreBinder
Kernel Extension to pin thread on a certain cpu core on Apple Silicon machines.(Also have the side effect to boost the frequecy to the max for that core).
The pre-compiled kext is for T6000/T6000. If you want to use it on T8112, compile it with -DT8112 flag.
# NOTE: USE AT YOUR OWN RISK
Unless you know what you are doing, otherwise don't use it.
# How to install?
1. You need to disable SIP first(unless you codesign the kext).
2. Switch to reduce security mode(https://softraid.com/faq/step-by-step-instructions-for-changing-the-security-settings-for-a-mac-with-apple-silicon/).
3. Move .kext folder under /Library/Extensions/. There will be a window pops up, follow the instrucion from there.
4. Run the command `sudo kextload /Library/Extensions/MacOS_CoreBinder.kext`.
# How to use?
After you had installed it, you can call the syscall via `sysctlbyname("kern.pin_core", NULL, NULL, &core, sizeof(core))` or use the commandline tool I provided under commandline_tool folder.
# Acknowledgement
Thanks for the help from jht5132(https://tieba.baidu.com/home/main?fr=home&id=tb.1.7a7e3dba.vu9oHFoN6nhDwEfbdVfrrw&un=Jht5132) for testing the kext, without him this project won't be possible.
Screenshot provided by him.
![image](https://cdn.discordapp.com/attachments/1033643903607386173/1103665349309759548/Image_04-05-2023_at_20.51.JPG)
