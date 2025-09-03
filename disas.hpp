#include <udis86.h>
#include <string>
#include <cstring>

#if defined(_WIN64)
    #define TARGET_ARCH_64BIT
#else
    #define TARGET_ARCH_32BIT
#endif

#ifdef TARGET_ARCH_64BIT
    static const size_t DISAS_MODE = 64;
#else
    static const size_t DISAS_MODE = 32;
#endif

class Disassembler
{
private:
	ud_t udObj;
public:
    Disassembler() {
        ud_init(&udObj);
        ud_set_mode(&udObj, DISAS_MODE);
        ud_set_syntax(&udObj, UD_SYN_INTEL);
    }
    size_t DisasInst(
        unsigned char* instCode,
        unsigned int instCodeSize,
        uint64_t pc,
        std::string& asmString,
        std::string& hexString)
    {
        ud_set_pc(&udObj, pc);
        ud_set_input_buffer(&udObj, instCode, instCodeSize);

        if (ud_disassemble(&udObj)) {
            asmString = ud_insn_asm(&udObj);
            hexString = ud_insn_hex(&udObj);
            return ud_insn_len(&udObj);
        }
        else {
            return 0;
        }
    }
};