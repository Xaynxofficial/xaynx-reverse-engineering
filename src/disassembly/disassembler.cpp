#include "xrl/disassembler.hpp"

#include <algorithm>

#ifdef XRL_HAS_CAPSTONE
#if __has_include(<capstone/capstone.h>)
#include <capstone/capstone.h>
#include <capstone/arm64.h>
#include <capstone/x86.h>
#else
#include <capstone.h>  // pkg-config exposes .../include/capstone directly
#include <arm64.h>
#include <x86.h>
#endif
#endif

#include "xrl/util.hpp"

namespace xrl {

bool disassemblerCompiledIn() {
#ifdef XRL_HAS_CAPSTONE
    return true;
#else
    return false;
#endif
}

std::string disassemblerVersion() {
#ifdef XRL_HAS_CAPSTONE
    int major = 0, minor = 0;
    cs_version(&major, &minor);
    return "Capstone " + std::to_string(major) + "." + std::to_string(minor);
#else
    return "unavailable (built without Capstone)";
#endif
}

bool disassemblySupported(const BinaryInfo& info) {
    if (!disassemblerCompiledIn()) return false;
    switch (info.arch) {
        case Arch::X86: case Arch::X86_64: case Arch::Arm: case Arch::Arm64:
        case Arch::Mips: case Arch::PowerPC: case Arch::RiscV:
            return info.bits == 32 || info.bits == 64;
        default: return false;
    }
}

std::vector<StartPoint> knownStartPoints(const BinaryInfo& info, size_t maxExports) {
    std::vector<StartPoint> out;
    if (info.entryPoint)
        if (auto off = info.virtualToFileOffset(*info.entryPoint))
            out.push_back({"Entry point (" + hex(*info.entryPoint) + ")", *off, *info.entryPoint});
    for (const auto& s : info.sections) {
        if (s.kind != "section" || !s.executable || !s.hasFileData || !s.boundsValid) continue;
        out.push_back({"Section " + s.name + " (" + hex(s.virtualAddress) + ")", s.fileOffset, s.virtualAddress});
    }
    size_t n = 0;
    for (const auto& e : info.exports.items) {
        if (!e.address || n >= maxExports) continue;
        if (auto off = info.virtualToFileOffset(*e.address)) {
            out.push_back({"Export " + e.name + " (" + hex(*e.address) + ")", *off, *e.address});
            ++n;
        }
    }
    return out;
}

#ifdef XRL_HAS_CAPSTONE
namespace {
struct Config {
    cs_arch arch;
    unsigned mode;
    size_t step;  // bytes to skip on undecodable data
    std::string note;
};

std::optional<Config> configFor(const BinaryInfo& info) {
    const bool be = info.endian == Endian::Big;
    const unsigned endianMode = be ? unsigned{CS_MODE_BIG_ENDIAN} : unsigned{CS_MODE_LITTLE_ENDIAN};
    switch (info.arch) {
        case Arch::X86: return Config{CS_ARCH_X86, unsigned{CS_MODE_32}, 1, ""};
        case Arch::X86_64: return Config{CS_ARCH_X86, unsigned{CS_MODE_64}, 1, ""};
        case Arch::Arm:
            if (info.armThumb) return Config{CS_ARCH_ARM, unsigned{CS_MODE_THUMB} | endianMode, 2, "Decoded as Thumb-2."};
            return Config{CS_ARCH_ARM, unsigned{CS_MODE_ARM} | endianMode, 4,
                          "Decoded in ARM mode. ARM/Thumb interworking is not auto-detected; Thumb code will decode incorrectly."};
        case Arch::Arm64: return Config{CS_ARCH_ARM64, unsigned{CS_MODE_ARM} | endianMode, 4, ""};
        case Arch::Mips:
            return Config{CS_ARCH_MIPS, (info.bits == 64 ? unsigned{CS_MODE_MIPS64} : unsigned{CS_MODE_MIPS32}) | endianMode, 4, ""};
        case Arch::PowerPC:
            return Config{CS_ARCH_PPC, (info.bits == 64 ? unsigned{CS_MODE_64} : unsigned{CS_MODE_32}) | endianMode, 4, ""};
        case Arch::RiscV:
            return Config{CS_ARCH_RISCV, (info.bits == 64 ? unsigned{CS_MODE_RISCV64} : unsigned{CS_MODE_RISCV32}) | unsigned{CS_MODE_RISCVC}, 2, ""};
        default: return std::nullopt;
    }
}

std::optional<uint64_t> immediateTarget(const cs_insn* insn, cs_arch arch) {
    if (!insn->detail) return std::nullopt;
    if (arch == CS_ARCH_X86) {
        const auto& x86 = insn->detail->x86;
        for (uint8_t i = 0; i < x86.op_count; ++i)
            if (x86.operands[i].type == X86_OP_IMM) return static_cast<uint64_t>(x86.operands[i].imm);
    } else if (arch == CS_ARCH_ARM64) {
        const auto& arm64 = insn->detail->arm64;
        for (uint8_t i = arm64.op_count; i > 0; --i)
            if (arm64.operands[i - 1].type == ARM64_OP_IMM)
                return static_cast<uint64_t>(arm64.operands[i - 1].imm);
    }
    return std::nullopt;
}

bool conditionalBranch(const cs_insn* insn, cs_arch arch) {
    if (arch == CS_ARCH_X86) return insn->id != X86_INS_JMP;
    if (arch == CS_ARCH_ARM64) {
        const auto id = insn->id;
        if (id == ARM64_INS_CBZ || id == ARM64_INS_CBNZ || id == ARM64_INS_TBZ || id == ARM64_INS_TBNZ)
            return true;
        if (id == ARM64_INS_B && insn->detail) {
            const auto condition = insn->detail->arm64.cc;
            return condition != ARM64_CC_AL && condition != ARM64_CC_INVALID;
        }
    }
    return false;
}

void populateFlow(csh handle, const cs_insn* insn, cs_arch arch, Instruction& out) {
    if (!insn->detail) return;
    if (cs_insn_group(handle, insn, CS_GRP_CALL)) {
        out.flowTarget = immediateTarget(insn, arch);
        out.flow = out.flowTarget ? InstructionFlow::Call : InstructionFlow::IndirectCall;
    } else if (cs_insn_group(handle, insn, CS_GRP_RET) || cs_insn_group(handle, insn, CS_GRP_IRET)) {
        out.flow = InstructionFlow::Return;
    } else if (cs_insn_group(handle, insn, CS_GRP_JUMP)) {
        out.flowTarget = immediateTarget(insn, arch);
        if (conditionalBranch(insn, arch))
            out.flow = InstructionFlow::ConditionalBranch;
        else
            out.flow = out.flowTarget ? InstructionFlow::UnconditionalBranch : InstructionFlow::IndirectBranch;
    }
    if (out.flow != InstructionFlow::Call && out.flow != InstructionFlow::IndirectCall &&
        out.flow != InstructionFlow::ConditionalBranch &&
        out.flow != InstructionFlow::UnconditionalBranch &&
        out.flow != InstructionFlow::IndirectBranch) {
        if (arch == CS_ARCH_X86) {
            const auto& x86 = insn->detail->x86;
            for (uint8_t i = 0; i < x86.op_count; ++i) {
                const auto& operand = x86.operands[i];
                if (operand.type == X86_OP_MEM) {
                    const auto& mem = operand.mem;
                    if (mem.base == X86_REG_RIP && insn->address <= UINT64_MAX - insn->size) {
                        const uint64_t next = insn->address + insn->size;
                        if (mem.disp >= 0 && static_cast<uint64_t>(mem.disp) <= UINT64_MAX - next)
                            out.dataTargets.push_back(next + static_cast<uint64_t>(mem.disp));
                        else if (mem.disp < 0 && static_cast<uint64_t>(-(mem.disp + 1)) + 1 <= next)
                            out.dataTargets.push_back(next - (static_cast<uint64_t>(-(mem.disp + 1)) + 1));
                    } else if (mem.base == X86_REG_INVALID && mem.index == X86_REG_INVALID && mem.disp >= 0) {
                        out.dataTargets.push_back(static_cast<uint64_t>(mem.disp));
                    }
                }
            }
        } else if (arch == CS_ARCH_ARM64 && insn->id == ARM64_INS_ADR) {
            const auto& arm64 = insn->detail->arm64;
            for (uint8_t i = 0; i < arm64.op_count; ++i)
                if (arm64.operands[i].type == ARM64_OP_IMM)
                    out.dataTargets.push_back(static_cast<uint64_t>(arm64.operands[i].imm));
        }
        std::sort(out.dataTargets.begin(), out.dataTargets.end());
        out.dataTargets.erase(std::unique(out.dataTargets.begin(), out.dataTargets.end()), out.dataTargets.end());
    }
}
}  // namespace
#endif

DisasmResult disassemble(const BinaryInfo& info, std::span<const uint8_t> data, const DisasmRequest& req) {
    DisasmResult res;
    res.startOffset = req.fileOffset;
#ifndef XRL_HAS_CAPSTONE
    (void)data;
    res.error = "This build of Xaynx Reverse Lab was compiled without Capstone; disassembly is unavailable.";
    return res;
#else
    if (!disassemblySupported(info)) {
        res.error = std::string("Disassembly is not supported for architecture '") + info.archName + "'.";
        return res;
    }
    if (req.fileOffset >= data.size()) {
        res.error = "Start offset " + hex(req.fileOffset) + " is outside the file (size " + std::to_string(data.size()) + ").";
        return res;
    }
    const uint64_t avail = data.size() - req.fileOffset;
    const uint64_t len = std::min<uint64_t>(std::min<uint64_t>(req.maxBytes, avail), 16ull * 1024 * 1024);
    const size_t maxInsns = std::min<size_t>(req.maxInstructions, 100'000);

    if (auto va = info.fileOffsetToVirtual(req.fileOffset)) {
        res.startAddress = *va;
    } else {
        res.startAddress = req.fileOffset;
        res.addressIsFileOffset = true;
    }

    const auto cfg = configFor(info);
    if (!cfg) { res.error = "No Capstone configuration for this architecture."; return res; }
    res.note = cfg->note;
    if (res.addressIsFileOffset)
        res.note += std::string(res.note.empty() ? "" : " ") +
                    "Start offset is not inside a mapped section; addresses shown are file offsets.";

    csh h = 0;
    if (cs_open(cfg->arch, static_cast<cs_mode>(cfg->mode), &h) != CS_ERR_OK) {
        res.error = "Capstone failed to initialise for this architecture/mode.";
        return res;
    }
    cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
    cs_insn* insn = cs_malloc(h);
    if (!insn) { cs_close(&h); res.error = "Capstone allocation failure."; return res; }

    const uint8_t* code = data.data() + req.fileOffset;
    size_t remaining = static_cast<size_t>(len);
    uint64_t addr = res.startAddress;
    uint64_t off = req.fileOffset;
    while (remaining > 0 && res.instructions.size() < maxInsns) {
        const uint8_t* cur = code;
        size_t curLen = remaining;
        uint64_t curAddr = addr;
        Instruction out;
        out.address = addr;
        out.fileOffset = off;
        size_t consumed;
        if (cs_disasm_iter(h, &cur, &curLen, &curAddr, insn)) {
            consumed = insn->size;
            out.bytes.assign(insn->bytes, insn->bytes + insn->size);
            out.mnemonic = insn->mnemonic;
            out.operands = insn->op_str;
            populateFlow(h, insn, cfg->arch, out);
        } else {
            consumed = std::min(cfg->step, remaining);
            out.bytes.assign(code, code + consumed);
            out.mnemonic = ".byte";
            out.operands = hexBytes(out.bytes);
            out.valid = false;
        }
        res.instructions.push_back(std::move(out));
        code += consumed; remaining -= consumed; addr += consumed; off += consumed;
    }
    cs_free(insn, 1);
    cs_close(&h);
    res.ok = true;
    return res;
#endif
}

}  // namespace xrl
