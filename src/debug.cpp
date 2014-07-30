/** $lic$
 * Copyright (C) 2014 by Kai Jia <jia.kai66@gmail.com>
 *
 * This file is part of zsim.
 *
 * zsim is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation, version 2.
 *
 * If you use this software in your research, we request that you reference
 * the zsim paper ("ZSim: Fast and Accurate Microarchitectural Simulation of
 * Thousand-Core Systems", Sanchez and Kozyrakis, ISCA-40, June 2013) as the
 * source of the simulator in any publications that use this software, and that
 * you send us a citation of your work.
 *
 * zsim is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "debug.h"
#include "log.h"
#include "gperftools/sysinfo.h"

#include <libunwind.h>

#include <sys/time.h>
#include <sys/resource.h>

#include <vector>

struct MemmapEntry {
    uintptr_t low, high;
    std::string file;

    MemmapEntry(uint64_t low_, uint64_t high_, const char *file_):
        low(low_), high(high_), file(file_)
    {}
};

static uintptr_t stack_size;

static void __attribute__((constructor)) setup_stack_size() {
    struct rlimit rlim;
    getrlimit(RLIMIT_STACK, &rlim);
    stack_size = rlim.rlim_cur;
}


int get_app_backtrace(uintptr_t rbp, uintptr_t rsp, uintptr_t rip,
        void **stack, int max_depth) {
    unw_context_t uc;
    unw_cursor_t cursor;
    memset(&uc, 0, sizeof(uc));
    // unw_getcontext(&uc);
    uc.uc_mcontext.gregs[REG_RSP] = rsp;
    uc.uc_mcontext.gregs[REG_RBP] = rbp;
    uc.uc_mcontext.gregs[REG_RIP] = rip;
    unw_init_local(&cursor, &uc);

    int depth = 0, ret = -1;
    stack[depth ++] = reinterpret_cast<void*>(rip);
    long volatile *rbp_user = (long*)0x601278;
    while (depth < max_depth && (ret = unw_step(&cursor)) > 0) {
        unw_word_t ip;
        unw_get_reg(&cursor, UNW_REG_IP, &ip);
        stack[depth ++] = reinterpret_cast<void*>(ip);
    }

    assert_msg(ret >= 0, "failed to backtrace: unw_step returned %d", ret);

    static int cnt = 0;
    if (cnt >= 300) {
        printf("bp %d: ret=%d rbp=0x%zx rsp=0x%zx pc=0x%zx "
                "user_rbp=0x%lx\n", cnt, ret,
                rbp, rsp, rip, *rbp_user);
        print_backtrace(stack, depth);
        getchar();
    }
    cnt ++;


    return depth;
}

void print_backtrace(const void * const *stack, int depth) {
    std::vector<MemmapEntry> memmap;
    {
        ProcMapsIterator piter(0);
        uintptr_t lo, hi;
        char *fname;
        while (piter.Next(&lo, &hi, nullptr, nullptr, nullptr, &fname)) {
            if (fname && strlen(fname)) {
                memmap.emplace_back(lo, hi, fname);
                // fprintf(stderr, "memmap: 0x%zx-0x%zx: %s\n", lo, hi, fname);
            }
        }
    }

    for (int i = 0; i < depth; i ++) {
        fprintf(stderr, "============================\nframe %d/%d: %p\n",
                i, depth, stack[i]);
        auto addr = reinterpret_cast<uintptr_t>(stack[i]);
        bool found = false;
        for (auto &j: memmap)
            if (j.low <= addr && j.high >= addr) {
                char cmd[1024];

                // theoretically we should examine file content to find whether
                // it is a shared library; but who would name an executable with
                // .so ?
                if (j.file.find(".so") != std::string::npos)
                    addr -= j.low;

                snprintf(cmd, sizeof(cmd), "addr2line -p -i -f -C -e %s 0x%zx 1>&2",
                        j.file.c_str(), addr);
                if (system(cmd))
                    fprintf(stderr, "failed to exec: %s\n", cmd);
                found = true;
                break;
            }
        if (!found)
            fprintf(stderr, "not found in memory map\n");
    }
}

