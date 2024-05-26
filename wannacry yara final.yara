rule Yara_Example {
    
    meta: 
        last_updated = "2024-5-26"
        author = "Abdulah Ibrahim Alharas"
        description = "A Yara rule for wannacry ransomware"

    strings:
        // Fill out identifying strings and other criteria
        $string1 = "wnry" ascii
        $string2 = "wanaCrypt0r" ascii
        $string3 = "icalcs . /grant Everyone:F /T /C /Q" ascii
        $PE_magic_byte = "MZ"
        $file = "C:\%s\qeriuwjhrf" ascii
        $exe = "tasksche.exe" ascii
        $url = "http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii
        


    condition:
        // Fill out the conditions that must be met to identify the binary
       $PE_magic_byte at 0 and
       all of them
       
