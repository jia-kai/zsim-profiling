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
 * profile the program being simulated
 *
 * the program is sampled on phase end, and statistics are fed to gperftools
 * (https://code.google.com/p/gperftools/) for further processing
 */

#include "log.h"
#include "core.h"

#include <pin.H>

#include <cstdint>
#include <vector>

class StackContext {
    static BblInfo m_bbl_sentinel;
    const BblInfo *m_cur_bbl = &m_bbl_sentinel;

    // pc of call instr of outer frames
    std::vector<uintptr_t> m_backtrace;

    friend class AppProfiler;

    public:

        void update(const BblInfo *bbl) {
            using T = BblInfo::Type;
            if (unlikely(m_cur_bbl->type == T::END_WITH_CALL))
                m_backtrace.push_back(m_cur_bbl->addr + m_cur_bbl->bytes - 1);
            else if (unlikely(m_cur_bbl->type == T::END_WITH_RET))
                m_backtrace.pop_back();
            m_cur_bbl = bbl;
        };

        int depth() const {
            return m_backtrace.size() + 1;
        }

        void print() const;
};


void appprof_init();
void appprof_fini();

void appprof_instrument_img(IMG img);

/*!
 * application profiler per core
 */
class AppProfiler {
    uint64_t m_prev_cycle = 0, m_bbl_start_cycle = 0;
    std::vector<void*> m_stack_buf;
    static uint64_t sample_nr_cycle;
    friend void appprof_init();

    void do_update(int tid, uint64_t cur_cycle);

    public:
        static int enabled;

        // must be called after simulating each bbl
        void update(int tid, uint64_t cur_cycle) {
            if (enabled) {
                if (cur_cycle - m_prev_cycle > sample_nr_cycle)
                    do_update(tid, cur_cycle);
                m_bbl_start_cycle = cur_cycle;
            }
        }
};

/*!
 * resolve symbols and print backtrace to stderr
 */
void print_backtrace(const StackContext &ctx);
