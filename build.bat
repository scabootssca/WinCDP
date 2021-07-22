REM g++ main.cpp -o WinCDP.exe -I"npcap-sdk-1.07\Include"
REM gcc -Wall -g main.c cdpStructs.c -o WinCDP.exe -I"npcap-sdk-1.07\Include" -L"npcap-sdk-1.07\Lib" -lwpcap
gcc -Wall main.c cdpStructs.c -o WinCDP.exe -I"npcap-sdk-1.07\Include" -L"npcap-sdk-1.07\Lib" -lwpcap