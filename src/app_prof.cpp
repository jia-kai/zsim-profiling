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
#include "gperftools/profiledata.h"

#include <sys/time.h>
#include <sys/resource.h>

namespace gprof {

    constexpr int PROF_FREQ = 1000;
    /*
     * profil_count and related are copied from glibc
     */
    static u_short *samples;
    static size_t nsamples;
    static size_t pc_offset;
    static u_int pc_scale;
    static int prof_trigger_phase;

    static void instrument_img(IMG img);
    static inline void profil_count(size_t pc);
    static int rep_profil(u_short *sample_buffer, size_t size, size_t offset, u_int scale);
    static int rep_profile_frequency();
    static inline void on_core_phase_end(uint32_t tid, const AppProfContext &ctx);
}

namespace gperftools {
    lock_t profile_data_lock;
    static ProfileData profile_data;
    static int sample_phase, cur_phase;
    static uintptr_t stack_size;

    template<typename T>
    static T deref_ptr(uintptr_t ptr) {
        return reinterpret_cast<T>(*reinterpret_cast<uintptr_t*>(ptr));
    };

    static inline void on_core_phase_end(uint32_t tid, const AppProfContext &ctx);
    static void init();
    static void fini();
};



/* ===================== gprof begins =============================== */
void gprof::instrument_img(IMG img) {
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

void gprof::profil_count(size_t pc) {
    size_t i = (pc - pc_offset) / 2;
    if (sizeof (unsigned long long int) > sizeof (size_t))
        i = (unsigned long long int) i * pc_scale / 65536;
    else
        i = i / 65536 * pc_scale + i % 65536 * pc_scale / 65536;
    if (i < nsamples) {
        __sync_fetch_and_add(samples + i, 1);
    }
}


int gprof::rep_profil(u_short *sample_buffer, size_t size, size_t offset, u_int scale) {
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

int gprof::rep_profile_frequency() {
    return PROF_FREQ;
}

void gprof::on_core_phase_end(uint32_t tid, const AppProfContext &ctx) {
    static int nr_phase;
    if (__sync_add_and_fetch(&nr_phase, 1) == prof_trigger_phase) {
        __sync_sub_and_fetch(&nr_phase, prof_trigger_phase);
        profil_count(ctx.pc);
    }
}
/* ===================== gprof ends =============================== */


/* ===================== gperftools begins =============================== */
void gperftools::init() {
    if (!zinfo->gperftoolsOutputName)
        return;
    sample_phase = zinfo->gperftoolsSamplePhase;
    futex_init(&profile_data_lock);
    ProfileData::Options opt;
    opt.set_frequency((long long)zinfo->freqMHz * 1000000 / (
                zinfo->phaseLength * sample_phase));
    profile_data.Start(zinfo->gperftoolsOutputName, opt);

    struct rlimit rlim;
    getrlimit(RLIMIT_STACK, &rlim);
    stack_size = rlim.rlim_cur;
}

void gperftools::fini() {
    if (!zinfo->gperftoolsOutputName)
        return;
    profile_data.Stop();
}

void gperftools::on_core_phase_end(uint32_t tid, const AppProfContext &ctx) {
    if (sample_phase > 1) {
        if (__sync_add_and_fetch(&cur_phase, 1) != sample_phase)
            return;

        __sync_fetch_and_sub(&cur_phase, sample_phase);
    }

    constexpr int MAX_DEPTH = ProfileData::kMaxStackDepth;
    void *stack[MAX_DEPTH];
    stack[0] = reinterpret_cast<void*>(ctx.pc);
    int depth = 1;
    auto top = zinfo->stackCtxOnFuncEntry[tid].stack_top,
         bottom = top - stack_size;

    if (ctx.rsp >= bottom && ctx.rsp <= top) {
        stack[depth ++] = deref_ptr<void*>(ctx.rsp);

        // Check whether rbp lies in stack range during backtracing.
        // This could be wrong if the compiler decides to use rbp as a general
        // register for optimization and rbp happens to store a pointer inside the
        // stack
        if (ctx.rbp > ctx.rsp) {
            auto rbp = ctx.rbp;
            while (rbp < top && depth < MAX_DEPTH) {
                stack[depth ++] = deref_ptr<void*>(rbp + sizeof(void*));
                auto new_rbp = deref_ptr<uintptr_t>(rbp);
                if (new_rbp <= rbp)
                    break;
                rbp = new_rbp;
            }
        }
    }

    futex_lock(&profile_data_lock);
    profile_data.Add(depth, stack);
    futex_unlock(&profile_data_lock);
}
/* ===================== gperftools ends =============================== */

void appprof_init() {
    gperftools::init();
}

void appprof_fini() {
    gperftools::fini();
}

void appprof_instrument_img(IMG img) {
    gprof::instrument_img(img);
}

void appprof_on_core_phase_end(uint32_t tid, const AppProfContext &ctx) {
    if (gprof::samples)
        gprof::on_core_phase_end(tid, ctx);
    if (zinfo->gperftoolsOutputName)
        gperftools::on_core_phase_end(tid, ctx);
}
