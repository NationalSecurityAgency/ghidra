@SET /p CHOICE=Clean Sleigh?
@IF '%CHOICE%'=='y' CALL gradle cleanSleigh
CALL gradle x86:sleighCompile