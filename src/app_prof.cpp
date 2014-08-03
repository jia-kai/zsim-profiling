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

/*
 * profiling output file format:
 *
 * all binary integers are uint64 in local endianness
 *
 * profile = magic bbl_prof map
 *
 * magic = "zsimprof"
 *
 * bbl_prof = nr_entry:int bbl_entry*
 * bbl_entry = addr:int addr_last_instr:int hit_cnt:int self_cycle:int 
 *             branch_nr_mispred:int call_prof
 *
 * call_prof = nr_entry:int call_entry*
 * call_entry = dest_addr:int cnt:int cycle:int
 *
 * map = map_entry* map_entry_end
 * map_entry = begin_addr:int end_addr:int file:str
 * map_entry_end = 0:int 0:int "\x00"
 *
 * note that cycle in call_entry is the total cycles spent in callee and its
 * children; 
 */

#include "app_prof.h"
#include "debug.h"
#include "decoder.h"

#include <unordered_map>

BblInfo StackContext::m_bbl_sentinel;
bool AppProfiler::sm_enabled;
std::vector<AppProfiler*> AppProfiler::sm_instance;

struct AppProfiler::BblProfile {
    uint64_t nr_hit = 0, self_cycle = 0,
             branch_nr_mispred = 0;

    struct Outcall {
        uint64_t cnt = 0, cycle = 0;
        void add(uint64_t cycle_) {
            cnt ++;
            cycle += cycle_;
        }
    };

    // key is callee bbl id
    std::unordered_map<uint32_t, Outcall> outcall;

    const BblInfo *recent_callee = nullptr;

    void add(uint64_t cycle) {
        nr_hit ++;
        self_cycle += cycle;
    }

    void merge_with(const BblProfile &other) {
        nr_hit += other.nr_hit;
        self_cycle += other.self_cycle;
        branch_nr_mispred += other.branch_nr_mispred;
        for (auto &&oc: other.outcall) {
            auto &&t = outcall[oc.first];
            t.cnt += oc.second.cnt;
            t.cycle += oc.second.cycle;
        }
    }
};

void AppProfiler::init() {
    zinfo->stackCtxOnBBLEntry = new StackContext[MAX_THREADS];
    zinfo->appProfiler = new AppProfiler[MAX_THREADS];
    for (int i = 0; i < MAX_THREADS; i ++)
        zinfo->appProfiler[i].m_tid = i;
    sm_enabled = zinfo->profileOutputName != nullptr;
}

void AppProfiler::fini() {
    if (sm_enabled) {
        std::vector<BblProfile> merged;
        for (AppProfiler *i: sm_instance) {
            if (merged.empty())
                merged = i->m_bbl_profile;
            else {
                if (i->m_bbl_profile.size() > merged.size())
                    merged.resize(i->m_bbl_profile.size());
                for (size_t idx = 0; idx < i->m_bbl_profile.size(); idx ++)
                    merged[idx].merge_with(i->m_bbl_profile[idx]);
            }
        }
        FILE *fout = fopen(zinfo->profileOutputName, "wb");
        info("Dumping profile output to %s", zinfo->profileOutputName);
        dump_output(fout, merged);
        fclose(fout);
    }
    delete []zinfo->appProfiler;
    delete []zinfo->stackCtxOnBBLEntry;
}

void AppProfiler::dump_output(FILE *fout, const std::vector<BblProfile>& profile) {
    const char *MAGIC = "zsimprof";

    fputs(MAGIC, fout);

    auto write_int = [&](uint64_t val) {
        auto nr = fwrite(&val, sizeof(val), 1, fout);
        assert(nr == 1);
    };

    uint64_t nr_bbl = 0;

    for (auto &&i: profile)
        nr_bbl += (i.nr_hit != 0);

    write_int(nr_bbl);
    for (size_t idx = 0; idx < profile.size(); idx ++) {
        auto &&bprof = profile[idx];
        if (bprof.nr_hit) {
            // bbl
            auto bbl = Decoder::bblId2Ptr(idx);
            write_int(bbl->addr);
            write_int(bbl->addr_end() - 1);
            write_int(bprof.nr_hit);
            write_int(bprof.self_cycle);
            write_int(bprof.branch_nr_mispred);

            // call
            write_int(bprof.outcall.size());
            for (auto &&oc: bprof.outcall) {
                write_int(Decoder::bblId2Ptr(oc.first)->addr);
                write_int(oc.second.cnt);
                write_int(oc.second.cycle);
            }
        }
    }

    {
        // dump memory map
        fpos_t pos;
        if (fgetpos(fout, &pos))
            panic("failed to call fgetpos: %m");

        int nr = 0;
        write_int(nr);

        get_mem_map(0, [&](uintptr_t lo, uintptr_t hi, const char *perm, const char *path) {
            if (path && path[0] && perm[2] == 'x') {
                write_int(lo);
                write_int(hi);
                fputs(path, fout);
                fputc(0, fout);
                nr ++;
            }
        });

        if (fsetpos(fout, &pos))
            panic("failed to call fsetpos");

        write_int(nr);
    }
}

AppProfiler::AppProfiler() {
    sm_instance.push_back(this);
}

void AppProfiler::do_update(const BblInfo *bbl, uint64_t cycle) {
    if (unlikely(bbl->id >= m_bbl_profile.size())) {
        m_bbl_profile.resize(bbl->id * 3 / 2 + 1);
    }

    m_bbl_profile[bbl->id].add(cycle);

    auto &&ctx = zinfo->stackCtxOnBBLEntry[m_tid];

    using T = BblInfo::Type;
    auto prev_bbl = ctx.m_cur_bbl;
    if (unlikely(prev_bbl->type == T::END_WITH_CALL)) {
        // prev_bbl calls bbl, record current cycle in caller and start
        // counting in callee
        ctx.m_backtrace.emplace_back(prev_bbl, ctx.m_topframe_cycle);
        ctx.m_topframe_cycle = cycle;
        m_bbl_profile[prev_bbl->id].recent_callee = bbl;
    } else if (unlikely(prev_bbl->type == T::END_WITH_RET && !ctx.m_backtrace.empty())) {
        auto &&caller = ctx.m_backtrace.back();
        if (likely(caller.caller->addr_end() == bbl->addr)) {
            // prev_bbl returns to recorded caller
            // record call edge stat, and current cycle in caller is the sum
            // of recorded cycle and accum cycle in callee
            auto &&s = m_bbl_profile[caller.caller->id];
            s.outcall[s.recent_callee->id].add(ctx.m_topframe_cycle);
            s.recent_callee = nullptr;
            ctx.m_topframe_cycle += caller.total_cycle + cycle;
        } else {
            warn("not return to caller, stack corrupted? long jump?");
            ctx.m_topframe_cycle = cycle;
        }
        ctx.m_backtrace.pop_back();
    } else {
        ctx.m_topframe_cycle += cycle;
    }

    ctx.m_cur_bbl = bbl;
}

void StackContext::print(size_t max_depth) const {
    std::vector<void*> bp;
    bp.push_back(reinterpret_cast<void*>(m_cur_bbl->addr));
    for (auto i = m_backtrace.crbegin();
            i != m_backtrace.crend() && bp.size() < max_depth;
            i ++)
        bp.push_back(reinterpret_cast<void*>(i->caller->addr_end() - 1));
    print_backtrace(bp.data(), bp.size());
}

