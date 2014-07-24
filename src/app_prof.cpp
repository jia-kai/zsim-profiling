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

#include "app_prof.h"
#include "log.h"
#include "zsim.h"

constexpr int PROF_FREQ = 1000;
/*
 * profil_count and related are copied from glibc
 */
static u_short *samples;
static size_t nsamples;
static size_t pc_offset;
static u_int pc_scale;
static int prof_trigger_phase;

static inline void profil_count(void *pc);
static int rep_profil(u_short *sample_buffer, size_t size, size_t offset, u_int scale);
static int rep_profile_frequency();

void appprof_instrument_img(IMG img) {
    if (IMG_Name(img).find("libc.so") == std::string::npos)
        return;
    RTN rtn = RTN_FindByName(img, "profil");
    if (rtn != RTN_Invalid()) {
        RTN_Replace(rtn, (AFUNPTR)rep_profil);
        info("replace profil in %s", IMG_Name(img).c_str());
        rtn = RTN_FindByName(img, "__profile_frequency");
        assert(rtn != RTN_Invalid());
        RTN_Replace(rtn, (AFUNPTR)rep_profile_frequency);
    }
}

void profil_count(void *pc) {
    size_t i = (reinterpret_cast<size_t>(pc) - pc_offset) / 2;
    if (sizeof (unsigned long long int) > sizeof (size_t))
        i = (unsigned long long int) i * pc_scale / 65536;
    else
        i = i / 65536 * pc_scale + i % 65536 * pc_scale / 65536;
    if (i < nsamples) {
        // info("prof: t=%d pc=%p pc_offset=%zx", PIN_ThreadId(), pc, pc_offset);
        __sync_fetch_and_add(samples + i, 1);
    }
}


int rep_profil(u_short *sample_buffer, size_t size, size_t offset, u_int scale) {
    if (!sample_buffer) {
        samples = nullptr;
        warn("profiling disabled");
        return 0;
    }
    samples = sample_buffer;
    nsamples = size / sizeof *samples;
    pc_offset = offset;
    pc_scale = scale;
    prof_trigger_phase = (long long)zinfo->freqMHz * 1000000 /
        ((long long)zinfo->phaseLength * PROF_FREQ);
    warn("profiling enabled, prof_trigger_phase=%d", prof_trigger_phase);
    return 0;
}

int rep_profile_frequency() {
    return PROF_FREQ;
}

void appprof_on_core_phase_end(BblInfo *bbl) {
    static int nr_phase;
    if (samples) {
        if (__sync_add_and_fetch(&nr_phase, 1) >= prof_trigger_phase) {
            nr_phase = 0;
            // random offset to scatter the samples in a bbl
            int offset = int(rand() / (RAND_MAX + 1.0) * bbl->bytes);
            profil_count(reinterpret_cast<void*>(bbl->start_addr + offset));
        }
    }
}

