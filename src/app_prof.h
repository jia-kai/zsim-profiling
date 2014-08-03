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

#include <cstdint>
#include <vector>
#include <limits>

class StackContext {
    static BblInfo m_bbl_sentinel;
    const BblInfo *m_cur_bbl = &m_bbl_sentinel;

    // total cycles of the top frame since the function entry,
    // including children
    uint64_t m_topframe_cycle = 0;

    struct StackFrame {
        const BblInfo *caller;

        uint64_t total_cycle;

        StackFrame() = default;

        StackFrame(const BblInfo *caller_):
            caller(caller_)
        {}

        StackFrame(const BblInfo *caller_, uint64_t total_cycle_):
            caller(caller_), total_cycle(total_cycle_)
        {}
    };

    // frames except the current one
    std::vector<StackFrame> m_backtrace;

    friend class AppProfiler;

    void update_noprofiling(const BblInfo *bbl) {
        using T = BblInfo::Type;
        if (unlikely(m_cur_bbl->type == T::END_WITH_CALL))
            m_backtrace.emplace_back(m_cur_bbl);
        else if (unlikely(m_cur_bbl->type == T::END_WITH_RET))
            m_backtrace.pop_back();
        m_cur_bbl = bbl;
    };


    public:
        int depth() const {
            return m_backtrace.size() + 1;
        }

        void print(size_t max_depth = std::numeric_limits<size_t>::max()) const;
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
    void do_update(const BblInfo *bbl, uint64_t cycle);

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
        void update(const BblInfo *bbl, uint64_t cycle) {
            if (sm_enabled)
                do_update(bbl, cycle);
            else
                zinfo->stackCtxOnBBLEntry[m_tid].update_noprofiling(bbl);
        }
};

