import re
from _ctypes import pointer
from ctypes import c_int, POINTER, cast, c_float
import angr
import pefile
from angr.procedures.libc.printf import printf
from angr.procedures.libc.scanf import scanf
from tqdm import tqdm


class bcolors:
    OK = '\033[92m'  # GREEN
    WARNING = '\033[93m'  # YELLOW
    FAIL = '\033[91m'  # RED
    RESET = '\033[0m'  # RESET COLOR
    lightcyan = '\033[34m'
    Blue = '\033[96m'


##############
# Functions Hooks
##############

def Function_Hook(proj, fileN):
    # ________1d_____________
    if fileN == 'level1_d':
        proj.hook(0x4118e8, printf())
        proj.hook(0x41169f, scanf())
        proj.hook(0x412685, printf())
    # _________1c___________
    elif fileN == 'level1_c':
        proj.hook(0x00434298, printf())
        proj.hook(0x00433DD4, scanf())
    # _________1a____________
    elif fileN == 'level1_a':
        proj.hook(0x4010F0, printf())
        proj.hook(0x004010D3, scanf())
    # _________1b__________
    else:
        print("not hook !")


def Function_Hook2(proj, array1, array2):
    for i in range(0, len(array1)):
        proj.hook(int(hex(int(array1[i], 16)), 16), printf())
    for i in range(0, len(array2)):
        proj.hook(int(hex(int(array2[i], 16)), 16), scanf())


##############
# Functions of Conversion : bytes in int , bytes in float , bytes in ascii
##############

def Function_Conversion(a):
    print("                 Here are the possible passwords with different types:\n")
    print(bcolors.Blue, "                 1)  In ASCII :\n", bcolors.RESET)
    stra = a.hex()
    count = 0
    new = ''
    for i in stra:
        if i == '0':
            count += 1
        if count == 2:
            break
        new += i
    new = new[:len(new) - 1]
    abc = '0x' + new
    try:
        print(bcolors.lightcyan, "                 Replace the byte 'xd9' by your choice letter :-) \n\n",
              bcolors.RESET,
              bcolors.FAIL + "                 The possible Response is :", bcolors.RESET, bcolors.WARNING,
              bytes.fromhex(abc[2:]), '\n' + bcolors.RESET)
    except:
        print("         not conversion possible in ascii ...")
    print(bcolors.Blue, "                 2)  In Floating Point : \n", bcolors.RESET)
    try:
        B = a
        C = hex(int(B))
        i = int(C, 16)
        cp = pointer(c_int(i))
        fp = cast(cp, POINTER(c_float))
        print(bcolors.FAIL + "                   The possible Response is :", bcolors.WARNING, fp.contents.value,
              '\n' + bcolors.RESET)
        if fp.contents.value < 1:
            print(bcolors.lightcyan, "                 that does not seem to be the right answer :-( \n", bcolors.RESET)
    except:
        print("                 it is not convertible in float ")

    try:
        print(bcolors.Blue, "                 3)  In Integer : \n", bcolors.RESET)
        print(bcolors.FAIL + "                   The possible Response is :", bcolors.WARNING, int(a),
              '\n' + bcolors.RESET)
    except:
        print("                 it is not convertible in integer ")


##############
# Convert physical address in Virtual Address
##############
def Function_find_virtual_address(path):
    fin = open(path, "rb")
    dat = fin.read()
    fin.close()
    pe = pefile.PE(path)
    count = 1
    b = ''
    for s in pe.sections:
        print("section number ", count, hex(s.PointerToRawData))
        if hex(s.PointerToRawData) == "0x400":
            b = hex(s.VirtualAddress)
            break
        else:
            count += 1
    return b, dat


def Function_find_virtual_address2(path):
    fin = open(path, "rb")
    dat = fin.read()
    fin.close()
    pe = pefile.PE(path)
    count = 1
    b = ''
    for s in pe.sections:
        print("section number ", count, hex(s.PointerToRawData))
        if hex(s.PointerToRawData) == "0x200":
            b = hex(s.VirtualAddress)
            break
        else:
            count += 1
    print(b)
    return b, dat


def main():
    print("  ", bcolors.OK, "     \U0001F432" * 12, bcolors.RESET)

    print(bcolors.OK,
          "               Welcome In the 'Automatic' Resolver of challenges (By J & N) \n"
          "               if you want to test the level 1a/1b/1c/1d please enter 1 \n   "
          "               and if you want to test your challenge please enter 2\n " + bcolors.RESET)
    choice = input()
    if choice == '1':
        print("Please enter your Path  \n")
        my_path = input()
        file = my_path.split('\\')
        fileN = file[len(file) - 1]
        proj = angr.Project(my_path)
        Function_Hook(proj, fileN)
        address_virtual, dat = Function_find_virtual_address(my_path)
        index_temp = 0
        a = None
        while a is None:
            if fileN == 'level1_b':
                pat = re.search(b"\x55\x89\xe5", dat[index_temp:])
            else:
                pat = re.search(b"\x55\x8b\xec", dat[index_temp:])
            index2 = (pat.span()[1])
            i = hex(pat.start() + index_temp)
            print("address in virtual ", i)
            print("index of Main is :", index2)
            result = int(i, 16) - int(str(400), 16)
            result += int(str(400000), 16)
            result += int(str(address_virtual), 16)
            print("the hex result of pseudo main is ", hex(result))

            start_address = hex(result)
            state = proj.factory.blank_state(addr=int(start_address, 16))
            sm = proj.factory.simulation_manager(state)
            if fileN == 'level1_a':
                sm.explore(find=0x0040102B, avoid=0x00401041, n=400)
            elif fileN == 'level1_b':
                sm.explore(find=0x0040139B, avoid=0x00401370, n=400)
            elif fileN == 'level1_c':
                sm.explore(find=0x00435A3F, avoid=0x00435A30, n=400)
            else:
                sm.explore(find=0x00412680, avoid=0x004126A6, n=400)
            print(sm.found)
            if sm.found == []:
                index_temp += index2
                loop = tqdm(total=5000, position=0, leave=False)
                temp = 5000
                k = 0
                while temp - k >= 0:
                    loop.set_description("Pass to the next pseudo-main ...".format(k))
                    loop.update(1)
                    k += 1
                loop.close()
                print("Waiting . . . . . . .")
            else:
                found = sm.found[0]
                a = found.posix.dumps(0)
                print(a)
                Function_Conversion(a)
        print('\n')
    elif choice == '2':
        print("Please enter the path of your file :\n")
        new_file_input = input()
        print("Please enter your address find in the form : 0x4000000 :\n")
        temp = input()
        address_find = (hex(int(temp, 16)))
        print("Have you need to hooks functions ? [yes/no]\n")
        reponse = input()
        if reponse == 'yes':
            print("please enter your list of  functions printf address in the form : 0x401,0x402,0x403 :\n")
            array_printf = input().split(',')
            print("please enter an array with your functions scanf address in the form : 0x401,0x402,0x403:\n")
            array_scanf = input().split(',')
            proj = angr.Project(new_file_input)
            Function_Hook2(proj, array_printf, array_scanf)
            fin = open(new_file_input, "rb")
            fin.close()
            pe = pefile.PE(new_file_input)
            if (pe.OPTIONAL_HEADER.name) == 'IMAGE_OPTIONAL_HEADER':
                address_virtual, dat = Function_find_virtual_address(new_file_input)
            else:
                address_virtual, dat = Function_find_virtual_address2(new_file_input)
            index_temp = 0
            a = None
            while a is None:
                pat = re.search(b"\x55\x8b\xec", dat[index_temp:])
                index2 = (pat.span()[1])
                i = hex(pat.start() + index_temp)
                result = int(i, 16) - int(str(400), 16)
                result += int(str(400000), 16)
                result += int(str(address_virtual), 16)

                start_address = hex(result)
                state = proj.factory.blank_state(addr=int(start_address, 16))
                sm = proj.factory.simulation_manager(state)
                sm.explore(find=int(address_find, 16), n=400)
                print(sm.found)
                if sm.found == []:
                    index_temp += index2
                    loop = tqdm(total=5000, position=0, leave=False)
                    temp = 5000
                    k = 0
                    while temp - k >= 0:
                        loop.set_description("Pass to the next pseudo-main ...".format(k))
                        loop.update(1)
                        k += 1
                    loop.close()
                    print("Waiting . . . . . . .")
                else:
                    found = sm.found[0]
                    a = found.posix.dumps(0)
                    print(a)
                    Function_Conversion(a)
            print('\n')
        else:
            proj = angr.Project(new_file_input)
            fin = open(new_file_input, "rb")
            fin.close()
            pe = pefile.PE(new_file_input)
            if pe.OPTIONAL_HEADER.name == 'IMAGE_OPTIONAL_HEADER':
                address_virtual, dat = Function_find_virtual_address(new_file_input)
            else:
                address_virtual, dat = Function_find_virtual_address2(new_file_input)
            index_temp = 0
            a = None
            while a is None:
                pat = re.search(b"\x89\xe5", dat[index_temp:])
                index2 = (pat.span()[1])
                i = hex(pat.start() + index_temp)
                result = int(i, 16) - int(str(400), 16)
                result += int(str(400000), 16)
                result += int(str(address_virtual), 16)

                start_address = hex(result)
                state = proj.factory.blank_state(addr=int(start_address, 16))
                sm = proj.factory.simulation_manager(state)
                sm.explore(find=int(address_find, 16), n=400)
                print(sm.found)
                if sm.found == []:
                    index_temp += index2
                    loop = tqdm(total=5000, position=0, leave=False)
                    temp = 5000
                    k = 0
                    while temp - k >= 0:
                        loop.set_description("Pass to the next pseudo-main ...".format(k))
                        loop.update(1)
                        k += 1
                    loop.close()
                    print("Waiting . . . . . . .")
                else:
                    found = sm.found[0]
                    a = found.posix.dumps(0)
                    print(bcolors.FAIL, "        This is the response in bits :", a, bcolors.RESET)
                    if a == b'':
                        memory = found.memory.load(found.regs.rcx, 128)
                        answer = found.solver.eval(memory, cast_to=bytes)
                        out = answer[:answer.index(b'\x00')]
                        print("Hex output: 0x{}".format(out.hex()))
                        print("Raw string output: {}".format(out))
                        print(found.posix.dumps(0).decode("utf-8"))
                    Function_Conversion(a)
            print('\n')


if __name__ == '__main__':
    main()
