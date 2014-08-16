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

#pragma once

/*
 * provides StackContext for backtracing and AppProfiler for profiling
 */

#include "log.h"
#include "core.h"
#include "zsim.h"

#include <pin.H>

#include <cstdint>
#include <vector>
#include <limits>
#include <unordered_map>

class ProfileCost {
    static constexpr int NR_METRIC = 2;
    static const char* METRIC_NAME[NR_METRIC];
    uint64_t m_cycle, m_branch_nr_mispred;

    friend class AppProfiler;

    public:
        ProfileCost() = default;

        ProfileCost(uint64_t cycle, uint64_t branch_nr_mispred = 0):
            m_cycle(cycle), m_branch_nr_mispred(branch_nr_mispred)
        {
        }
    
        void merge_with(const ProfileCost &c) {
            m_cycle += c.m_cycle;
            m_branch_nr_mispred += c.m_branch_nr_mispred;
        }
};

class StackContext {
    static BblInfo m_bbl_sentinel;
    const BblInfo
        *m_cur_bbl = &m_bbl_sentinel,   // current BBL processed by the core
        *m_cur_exe_bbl = nullptr;       // actual BBL currently being executed

    // total cycles of the top frame since the function entry,
    // including children
    ProfileCost m_topframe_cost = 0;

    struct StackFrame {
        /*
         * jmp to another function, caused by optimized sibling and tail
         * recursive calls, would also be considered as call and result in a
         * stack frame. is_actual_call is used to distinguish jmp from actual
         * call
         */
        bool is_actual_call;

        const BblInfo *caller, *callee;

        ProfileCost total_cost;

        StackFrame() = default;

        StackFrame(bool is_actual_call_, const BblInfo *caller_):
            is_actual_call(is_actual_call_), caller(caller_)
        {}

        StackFrame(bool is_actual_call_, const BblInfo *caller_,
                const BblInfo *callee_, const ProfileCost &total_cost_):
            is_actual_call(is_actual_call_),
            caller(caller_), callee(callee_), total_cost(total_cost_)
        {}
    };

    // frames except the current one
    std::vector<StackFrame> m_backtrace;

    friend class AppProfiler;

    void update_noprofiling(const BblInfo *bbl) {
        using T = BblInfo::Type;
        auto prev_bbl = m_cur_bbl;
        bool is_call = prev_bbl->type == T::END_WITH_CALL;
        if (unlikely(m_cur_bbl->type == T::END_WITH_RET)) {
            while (!m_backtrace.back().is_actual_call)
                m_backtrace.pop_back();
            m_backtrace.pop_back();
        } else if (unlikely(is_call || prev_bbl->rtnId != bbl->rtnId))
            m_backtrace.emplace_back(is_call, m_cur_bbl);
        m_cur_bbl = bbl;
    };


    public:
        int depth() const {
            return m_backtrace.size() + 1;
        }

        void on_exe_bbl_enter(const BblInfo *bbl) {
            m_cur_exe_bbl = bbl;
        }

        void print(size_t max_depth = std::numeric_limits<size_t>::max()) const;
};


/*!
 * manages routines resolved by PIN
 */
class RTNManager {
    struct RTNEntry {
        uint32_t id = 0, size;
    };
    // rtn address to rtn size
    lock_t m_mutex = 0;
    std::unordered_map<uint64_t, RTNEntry> m_addr2entry;

    RTNManager() = default;
    RTNManager(const RTNManager &) = delete;
    RTNManager& operator = (const RTNManager &) = delete;

    friend class AppProfiler;

    public:
        static RTNManager& ins();

        uint32_t get_id(TRACE trace);
};


/*!
 * each thread must have its own AppProfiler, so there is no need to lock
 */
class AppProfiler {
    static bool sm_enabled;
    static std::vector<AppProfiler*> sm_instance;

    struct BblProfile;
    std::vector<BblProfile> m_bbl_profile;
    int m_tid;

    AppProfiler();

    void do_update(const BblInfo *bbl, const ProfileCost &cost);
    void exit_all_frame();

    static void dump_output(FILE *fout, const std::vector<BblProfile>& profile);

    public:

        // on zsim init
        static void init();

        // on zsim exit
        static void fini();

        /*
         * must be called after simulating each bbl to update profiling data
         * \param cur_cycle core cycle count after finishing this bbl
         */
        void update(const BblInfo *bbl, const ProfileCost &cost) {
            if (sm_enabled)
                do_update(bbl, cost);
            else
                zinfo->stackCtxOnBBLEntry[m_tid].update_noprofiling(bbl);
        }
};

