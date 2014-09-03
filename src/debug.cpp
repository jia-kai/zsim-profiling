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
#include "zsim.h"
#include "app_prof.h"

#include <pin.H>
#include <execinfo.h>

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

void get_mem_map(int pid, std::function<void(uintptr_t, uintptr_t, const char*, const char*)> callback) {
    char fpath[64];
    if (pid)
        sprintf(fpath, "/proc/%d/maps", pid);
    else
        strcpy(fpath, "/proc/self/maps");
    FILE *fin = fopen(fpath, "r");
    assert_msg(fin, "failed to open %s", fpath);
    char linebuf[512];
    while (fgets(linebuf, sizeof(linebuf), fin)) {
        uintptr_t begin, end;
        char perm[10], offset[20], dev[10], inode[20], path_mem[256], *path;
        int nr = sscanf(linebuf, "%zx-%zx %s %s %s %s %s",
                &begin, &end, perm, offset, dev, inode, path_mem);
        if (nr == 6)
            path = nullptr;
        else {
            assert_msg(nr == 7, "failed to parse map line: %s", linebuf);
            path = path_mem;
        }
        callback(begin, end, perm, path);
    }
    fclose(fin);
}

void print_backtrace(const void * const *stack, int depth) {
    std::vector<MemmapEntry> memmap;
    get_mem_map(0, [&](uintptr_t lo, uintptr_t hi, const char *perm, const char *fname){
        if (fname && strlen(fname))
            memmap.emplace_back(lo, hi, fname);
    });

    for (int i = 0; i < depth; i ++) {
        fprintf(stderr, "#%-3d ", i);
        fflush(stderr);
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

                snprintf(cmd, sizeof(cmd), "addr2line -a -p -i -f -C -e %s 0x%zx 1>&2",
                        j.file.c_str(), addr);
                if (system(cmd))
                    fprintf(stderr, "   failed to exec: %s\n", cmd);
                found = true;
                break;
            }
        if (!found)
            fprintf(stderr, "0x%016zx <not found in memory map>\n", addr);
    }
}

void print_backtrace_zsim() {
    constexpr int MAX_DEPTH = 20;
    void *stack[MAX_DEPTH];
    int depth = backtrace(stack, MAX_DEPTH);

    // use the addr of call instruction
    for (int i = 0; i < depth; i ++)
      stack[i] = (void*)((uintptr_t)stack[i] - 1);

    fprintf(stderr, "%s[%d] backtrace of pin/zsim:\n", logHeader, PIN_ThreadId());
    print_backtrace(stack, depth);
}

void print_backtrace_app(int tid) {
    constexpr int MAX_DEPTH = 20;
    if (tid == -1)
        tid = PIN_ThreadId();
    auto &&ctx = zinfo->stackCtxOnBBLEntry[tid];
    fprintf(stderr, "%s[%d] backtrace of simulated prog: frames=%d\n",
            logHeader, tid, ctx.depth());
    ctx.print(MAX_DEPTH);
}
