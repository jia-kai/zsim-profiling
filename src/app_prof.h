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
 * profile the application being simulated
 *
 * the program is sampled on phase end, and statistics are fed to gperftools
 * (https://code.google.com/p/gperftools/) for further processing
 */

#include <pin.H>

#include "log.h"

struct AppProfContext {
    uintptr_t rbp, rsp, pc;

    AppProfContext(uintptr_t rbp_, uintptr_t rsp_,
            uintptr_t bbl_start, uintptr_t bbl_length,
            uint64_t start_cycle, uint64_t cur_cycle, uint64_t end_cycle):
        rbp(rbp_), rsp(rsp_),

        // assume all instructions have same length to calc pc
        pc(bbl_start + bbl_length * (cur_cycle - start_cycle) / (end_cycle - start_cycle))
    {
        assert_msg(cur_cycle >= start_cycle && cur_cycle <= end_cycle,
                "phase=%zd-%zd cur_cycle=%zx", start_cycle, end_cycle, cur_cycle);
    }
};

void appprof_init();
void appprof_fini();

void appprof_instrument_img(IMG img);

void appprof_on_core_phase_end(uint32_t tid, const AppProfContext &ctx);
