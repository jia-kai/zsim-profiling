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
 * profile = magic cost_desc bbl_prof rtn_list mem_map
 *
 * magic = "zsimprof"
 *
 * cost_desc = nr_cost:int cost_name:str*
 *
 * bbl_prof = nr_entry:int bbl_entry*
 * bbl_entry = addr:int addr_last_instr:int hit_cnt:int cost call_prof
 *
 * call_prof = nr_entry:int call_entry*
 * call_entry = dest_addr:int cnt:int cost
 *
 * rtn_list = nr_rtn_list:int rtn_entry*
 * rtn_entry = begin:int end:int
 *
 * mem_map = nr_entry:int map_entry*
 * map_entry = begin_addr:int end_addr:int file:str
 *
 * cost = cost_item:int*
 *
 * note that cycle in call_entry is the total cycles spent in callee and its
 * children; 
 */

#include "app_prof.h"
#include "debug.h"
#include "decoder.h"

#include <type_traits>

// #define DUMP_CALL

BblInfo StackContext::m_bbl_sentinel;
bool AppProfiler::sm_enabled;
std::vector<AppProfiler*> AppProfiler::sm_instance;

const char* ProfileCost::METRIC_NAME[ProfileCost::NR_METRIC] = {
    "cycle", "branch_nr_mispred"
};

struct AppProfiler::BblProfile {
    uint64_t nr_hit = 0;
    ProfileCost self_cost;

    struct Outcall {
        uint64_t cnt = 0;
        ProfileCost cost;
        void add(const ProfileCost &cost_) {
            cnt ++;
            cost.merge_with(cost_);
        }
    };

    // key is callee bbl id
    std::unordered_map<uint32_t, Outcall> outcall;

    void add(const ProfileCost &cost) {
        nr_hit ++;
        self_cost.merge_with(cost);
    }

    void merge_with(const BblProfile &other) {
        nr_hit += other.nr_hit;
        self_cost.merge_with(other.self_cost);
        for (auto &&oc: other.outcall) {
            auto &&t = outcall[oc.first];
            t.cnt += oc.second.cnt;
            t.cost.merge_with(oc.second.cost);
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
            i->exit_all_frame();
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
        assert_msg(fout, "failed to open `%s' for profiling output", zinfo->profileOutputName);
        info("Dumping profiling output to %s", zinfo->profileOutputName);
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

    auto write_cost = [&](const ProfileCost &val) {
        static_assert(sizeof(ProfileCost) == sizeof(uint64_t) * ProfileCost::NR_METRIC &&
                std::is_pod<ProfileCost>::value, "bad ProfileCost");
        auto nr = fwrite(&val, sizeof(ProfileCost), 1, fout);
        assert(nr == 1);
    };

    auto write_str = [&](const char *s) {
        fputs(s, fout);
        fputc(0, fout);
    };

    {
        // dump cost description
        write_int(ProfileCost::NR_METRIC);
        for (int i = 0; i < ProfileCost::NR_METRIC; i ++)
            write_str(ProfileCost::METRIC_NAME[i]);
    }

    {
        // dump bbl
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
                write_int(bbl->addr_last_instr());
                write_int(bprof.nr_hit);
                write_cost(bprof.self_cost);

                // call
                write_int(bprof.outcall.size());
                for (auto &&oc: bprof.outcall) {
                    write_int(Decoder::bblId2Ptr(oc.first)->addr);
                    write_int(oc.second.cnt);
                    write_cost(oc.second.cost);
                }
            }
        }
    }

    {
        // dump rtn list
        auto &&data = RTNManager::ins().m_addr2entry;
        write_int(data.size());
        for (auto &&i: data) {
            write_int(i.first);
            write_int(i.second.size);
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
                write_str(path);
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

#ifdef DUMP_CALL
static std::vector<std::string> rtn_id2name;
static lock_t print_lock;
#endif

void AppProfiler::do_update(const BblInfo *bbl, const ProfileCost &cost) {
    if (unlikely(bbl->id >= m_bbl_profile.size())) {
        m_bbl_profile.resize(bbl->id * 3 / 2 + 1);
    }

    m_bbl_profile[bbl->id].add(cost);

    auto &&ctx = zinfo->stackCtxOnBBLEntry[m_tid];

    using T = BblInfo::Type;
    auto prev_bbl = ctx.m_cur_bbl;
    bool is_call = prev_bbl->type == T::END_WITH_CALL;
    if (unlikely(prev_bbl->type == T::END_WITH_RET)) {
        // prev_bbl returns to recorded caller, which should proceed current rtn
        auto inclusive_cost = ctx.m_topframe_cost;
        StackContext::StackFrame *caller_frame;
        for (; ; ) {
            caller_frame = &ctx.m_backtrace.back();
#ifdef DUMP_CALL
            futex_lock(&print_lock);
            printf("[%d] exit call: %s(%zx)=>%s(%zx)\n", 
                    m_tid,
                    rtn_id2name[caller_frame->caller->rtnId].c_str(), caller_frame->caller->addr,
                    rtn_id2name[caller_frame->callee->rtnId].c_str(), caller_frame->callee->addr);
            futex_unlock(&print_lock);
#endif
            m_bbl_profile[caller_frame->caller->id].
                outcall[caller_frame->callee->id].add(inclusive_cost);
            inclusive_cost.merge_with(caller_frame->total_cost);
            if (caller_frame->is_actual_call)
                break;
            ctx.m_backtrace.pop_back();
        }
        if (likely(caller_frame->caller->addr_end() == bbl->addr)) {
            inclusive_cost.merge_with(cost);
            ctx.m_topframe_cost = inclusive_cost;
        } else {
            warn("not return to caller, stack corrupted? long jump?");
            ctx.m_topframe_cost = cost;
        }
        ctx.m_backtrace.pop_back();
    } else if (unlikely(is_call || prev_bbl->rtnId != bbl->rtnId)) {
        // if the instr is not ret, and prev_bbl and bbl belong to different
        // rtns, assume prev_bbl calls bbl

#ifdef DUMP_CALL
        futex_lock(&print_lock);
        printf("[%d] enter call: %s(%zx)=>%s(%zx)\n", 
                m_tid,
                rtn_id2name[prev_bbl->rtnId].c_str(), prev_bbl->addr,
                rtn_id2name[bbl->rtnId].c_str(), bbl->addr);
        futex_unlock(&print_lock);
#endif

        ctx.m_backtrace.emplace_back(
                is_call, prev_bbl, bbl, ctx.m_topframe_cost);
        ctx.m_topframe_cost = cost;
    } else {
        ctx.m_topframe_cost.merge_with(cost);
    }

    ctx.m_cur_bbl = bbl;
}

void AppProfiler::exit_all_frame() {
    auto &&ctx = zinfo->stackCtxOnBBLEntry[m_tid];
    auto inclusive_cost = ctx.m_topframe_cost;
    while (!ctx.m_backtrace.empty()) {
        auto &&caller_frame = ctx.m_backtrace.back();
        m_bbl_profile[caller_frame.caller->id].
            outcall[caller_frame.callee->id].add(inclusive_cost);
        inclusive_cost.merge_with(caller_frame.total_cost);
        ctx.m_backtrace.pop_back();
    }
}

void StackContext::print(size_t max_depth) const {
    StackContext copy(*this);
    if (m_cur_bbl != m_cur_exe_bbl)
        copy.update_noprofiling(m_cur_exe_bbl);
    std::vector<void*> bp;
    bp.push_back(reinterpret_cast<void*>(copy.m_cur_bbl->addr));
    for (auto i = copy.m_backtrace.rbegin();
            i != copy.m_backtrace.rend(); i ++) {
        bp.push_back(reinterpret_cast<void*>(i->caller->addr_last_instr()));
        if (bp.size() >= max_depth)
            break;
    }
    print_backtrace(bp.data(), bp.size());
}

RTNManager& RTNManager::ins() {
    static RTNManager r;
    return r;
}

uint32_t RTNManager::get_id(TRACE trace) {
    RTN rtn = TRACE_Rtn(trace);
    if (!RTN_Valid(rtn)) {
        return 0;
    }
    ADDRINT addr = RTN_Address(rtn);
    bool is_plt = false;
    if (RTN_Name(rtn) == ".plt") {
        addr = TRACE_Address(trace) & ~0xFull;
        is_plt = true;
    }
    futex_lock(&m_mutex);
    RTNEntry &entry = m_addr2entry[addr];
    if (unlikely(!entry.id)) {
        entry.id = m_addr2entry.size();
        entry.size = is_plt ? 0x10 : RTN_Range(rtn);
        auto trace_addr = TRACE_Address(trace);
        assert(trace_addr >= addr &&
                trace_addr < addr + entry.size);
#ifdef DUMP_CALL
        rtn_id2name.resize(entry.id + 1);
        rtn_id2name[entry.id] = RTN_Name(rtn);
#endif
    }
    futex_unlock(&m_mutex);
    return entry.id;
}

