import idaapi
import idautils
import idc
import ida_dbg
import ida_frame
import ida_struct


"""
1) buffer overflow : scanf
1a)fct qui trouve les fct vulnerables liees a notre attack , stocker leur addresse
1b)lazy ida : breakpoints sur les addresses vulnerables
1c)retracer tous les parameters
1d)analyser les parameters : si ils sont liees a un scanf , une fct de input ou a un locale


2) FORMAT STRING ATTACK : printf

3)HEAP OVERFLOW :  memcpy


4)INTEGER OVERFLOW

5) MACRO INPUT

6)  do  plugin

"""

note = "CharToOem, CharToOemA, CharToOemBuffA, CharToOemBuffW, CharToOemW,IsBadCodePtr, IsBadHugeReadPtr, IsBadHugeWritePtr, IsBadReadPtr,IsBadStringPtr, IsBadWritePtr, Makepath, OemToChar, OemToCharA,OemToCharW, StrCat, StrCatA, StrCatBuff, StrCatBuffA, StrCatBuffW,StrCatChainW, StrCatN, StrCatNA, StrCatNW, StrCatW, StrCpy, StrCpyA,StrCpyN, StrCpyNA, StrCpyNW, StrCpyW, StrLen, StrNCat, StrNCatA,StrNCatW, StrNCpy, StrNCpyA, StrNCpyW, _alloca, _fstrncat, _fstrncpy,_getts, _gettws, _i64toa, _i64tow, _itoa, _itow, _makepath, _mbccat,_mbccpy, _mbscat, _mbscpy, _mbslen, _mbsnbcat, _mbsnbcpy, _mbsncat,_mbsncpy, _mbstok, _mbstrlen, _snprintf, _sntprintf, _sntscanf,_snwprintf, _splitpath, _stprintf, _stscanf, _tccat, _tccpy, _tcscat,_tcscpy, _tcsncat, _tcsncpy, _tcstok, _tmakepath, _tscanf, _tsplitpath,_ui64toa, _ui64tot, _ui64tow, _ultoa, _ultot, _ultow, _vsnprintf,_vsntprintf, _vsnwprintf, _vstprintf, _wmakepath, _wsplitpath, alloca,gets, lstrcat, lstrcatA, lstrcatW, lstrcatn, lstrcatnA, lstrcatnW,lstrcpy, lstrcpyA, lstrcpyW, lstrcpyn, lstrcpynA, lstrcpynW, lstrlen,lstrncat, nsprintf, scanf, snscanf, snwscanf, sprintf, sprintfA,sprintfW, sscanf, strcat, strcatA, strcatW, strcpy, strcpyA, strcpyW,strcpynA, strlen, strncat, strncpy, strtok, swprintf, swscanf, vsprintf,vswprintf, wcscat, wcscpy, wcslen, wcsncat, wcsncpy, wcstok, wnsprintf,wnsprintfA, wnsprintfW, wscanf, wsprintf, wsprintfA, wsprintfW,wvnsprintf, wvnsprintfA, wvnsprintfW, wvsprintf, wvsprintfA, wvsprintfW"
Tableau_scanf =[] # buffer overflow and string attack
Tableau_printf =[] # string attack and buffer overflow
Tableau_cpy =[]  # buffer overflow
Tableau_cat =[]  # buffer overflow
Tableau_len =[]   # buffer overread
Tableau_get =[] # string attack
Tableau_mem =[] # jsp


def fonction_first_param(i,asm):
    if asm in Tableau_scanf :
        prev=(prev_head(i))
        asm_1 =idc.GetDisasm(prev)
        return asm_1[8:11]

def get_value_of_this_register(i,register):
    prev=(prev_head(i))
    asm_1 =idc.GetDisasm(prev)
    temp_register = asm_1[13:] 
    print("temp register is ",temp_register)
    
    while asm_1[8:11] != temp_register and asm_1[0:4] !='call':
        i = prev
        prev=(prev_head(i))
        asm_1 =idc.GetDisasm(prev)
   
    return (asm_1[13:],i)


def GET_ALL_FUNCTIONS():
    DATABASE_FUNCTIONS = note.split(',')
    DATABASE_FUNCTIONS.sort()
    for i in range(len(DATABASE_FUNCTIONS)):
        str = DATABASE_FUNCTIONS[i]
        if str[0] == ' ':
            DATABASE_FUNCTIONS[i] = str[1:]
    print(DATABASE_FUNCTIONS)
    for i in DATABASE_FUNCTIONS:
        if 'scanf'.upper() in i.upper():
            Tableau_scanf.append(i)
        elif 'printf'.upper() in i.upper():
            Tableau_printf.append(i)
        elif 'cpy'.upper() in i.upper():
            Tableau_cpy.append(i)
        elif 'cat'.upper() in i.upper():
            Tableau_cat.append(i)
        elif 'len'.upper() in i.upper():
            Tableau_len.append(i)
        elif 'get'.upper() in i.upper():
            Tableau_get.append(i)
        elif 'mem'.upper() in i.upper():
            Tableau_mem.append(i)
    Tableau_printf.append('printf')
    
    
    
    
    
def case_basic_scanf_64bits():
    param1 =0
    head=idautils.Heads()
    for i in head:
        asm_1=idc.GetDisasm(i)
        if asm_1[0:4]=='call':
            
            if asm_1[8:] in Tableau_scanf:
                param1 = fonction_first_param(i,asm_1[8:]) #rdx
                print("first paramters before scanf : ",param1)
                value,i =get_value_of_this_register(i,param1) #rax 
                value2,i2 = get_value_of_this_register(i,value) #rbp+str2
                print(value2)
                if '+' in value2:
                    print("local variable ! ")
                else:
                    print("no")
                """frame = ida_frame.get_frame(i2)
                loc_var = ida_struct.get_member_by_name(frame, 'Str2')
                print("local variable ",loc_var)"""


if __name__ == '__main__':
    GET_ALL_FUNCTIONS()
    case_basic_scanf_64bits()
