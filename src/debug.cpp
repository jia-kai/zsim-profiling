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
#include "gperftools/sysinfo.h"

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

template<typename T>
static T deref_ptr(uintptr_t ptr) {
    return reinterpret_cast<T>(*reinterpret_cast<uintptr_t*>(ptr));
};


int get_app_backtrace(uintptr_t rbp, uintptr_t rsp, uintptr_t top,
        void **stack, int max_depth) {
    auto bottom = top - stack_size;

    if (rsp < bottom || rsp > top)
        return 0;

    int depth = 1;
    stack[0] = deref_ptr<void*>(rsp);

    // Check whether rbp lies in stack range during backtracing.
    // This could be wrong if the compiler decides to use rbp as a general
    // register for optimization and rbp happens to store a pointer inside the
    // stack
    if (rbp > rsp) {
        while (rbp < top && depth < max_depth) {
            stack[depth ++] = deref_ptr<void*>(rbp + sizeof(void*));
            auto new_rbp = deref_ptr<uintptr_t>(rbp);
            if (new_rbp <= rbp)
                break;
            rbp = new_rbp;
        }
    }
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

