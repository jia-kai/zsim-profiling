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
#include "debug.h"
#include "zsim.h"
#include "gperftools/profiledata.h"

static int get_profile_freq() {
    return zinfo->freqMHz * 1000000ll / zinfo->appProfConfig.sampleCycles;
}

constexpr int PROFILE_ENABLE_MASK_GPROF = 1, PROFILE_ENABLE_MASK_GPERFTOOLS = 2;
uint64_t AppProfiler::sample_nr_cycle;
int AppProfiler::enabled;

namespace gprof {
    /*
     * profil_count and related are copied from glibc
     */
    static u_short *samples;
    static size_t nsamples;
    static size_t pc_offset;
    static u_int pc_scale;

    static void instrument_img(IMG img);
    static int rep_profil(u_short *sample_buffer, size_t size, size_t offset, u_int scale);
    static inline void update(size_t pc);
}

namespace gperftools {
    constexpr size_t MAX_DEPTH = ProfileData::kMaxStackDepth;
    lock_t profile_data_lock;
    static ProfileData profile_data;

    static void init();
    static void fini();
    static inline void update(const void * const * stack, int depth) {
        futex_lock(&profile_data_lock);
        profile_data.Add(depth, stack);
        futex_unlock(&profile_data_lock);
    }
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
        RTN_Replace(rtn, (AFUNPTR)get_profile_freq);
    }
}

void gprof::update(size_t pc) {
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
    warn("profil called, sample_buffer=%p", sample_buffer);
    samples = sample_buffer;
    if (!sample_buffer) {
        AppProfiler::enabled = 0;
        return 0;
    }
    assert_msg(!AppProfiler::enabled,
            "another profiler other than gprof has been enabled");
    AppProfiler::enabled = PROFILE_ENABLE_MASK_GPROF;
    nsamples = size / sizeof *samples;
    pc_offset = offset;
    pc_scale = scale;
    return 0;
}

/* ===================== gprof ends =============================== */


/* ===================== gperftools begins =============================== */
void gperftools::init() {
    const char* out_name = zinfo->appProfConfig.gperftoolsOutputName;
    if (!out_name)
        return;
    assert_msg(!AppProfiler::enabled,
            "another profiler other than gperftools has been enabled");
    warn("enabled gperftools profiling, output: %s", out_name);
    AppProfiler::enabled = PROFILE_ENABLE_MASK_GPERFTOOLS;
    futex_init(&profile_data_lock);
    ProfileData::Options opt;
    opt.set_frequency(get_profile_freq());
    profile_data.Start(out_name, opt);
}

void gperftools::fini() {
    if (!zinfo->appProfConfig.gperftoolsOutputName)
        return;
    profile_data.Stop();
}

/* ===================== gperftools ends =============================== */

void appprof_init() {
    AppProfiler::sample_nr_cycle = zinfo->appProfConfig.sampleCycles;
    gperftools::init();
}

void appprof_fini() {
    gperftools::fini();
}

void appprof_instrument_img(IMG img) {
    gprof::instrument_img(img);
}

void AppProfiler::do_update(int tid, uint64_t cur_cycle) {
    uint64_t next_cycle = m_prev_cycle + sample_nr_cycle;
    assert_msg(next_cycle >= m_bbl_start_cycle,
            "bad cycle: prev=%zd next=%zd bbl=[%zx,%zd]",
            m_prev_cycle, next_cycle, m_bbl_start_cycle, cur_cycle);

    // calculate PC inside this bbl under assumption that each instr takes same
    // time and has same length

    auto bbl_nr_cycle = cur_cycle - m_bbl_start_cycle;
    auto &&ctx = zinfo->stackCtxOnBBLEntry[tid];
    if (enabled == PROFILE_ENABLE_MASK_GPERFTOOLS) {
        auto &&buf = m_stack_buf;
        buf.clear();
        buf.push_back(0);
        for (auto i = ctx.m_backtrace.crbegin();
                i != ctx.m_backtrace.crend() && buf.size() < gperftools::MAX_DEPTH;
                i ++)
            buf.push_back(reinterpret_cast<void*>(*i));

        while (next_cycle < cur_cycle) {
            auto addr = ctx.m_cur_bbl->addr +
                ctx.m_cur_bbl->bytes * (next_cycle - m_bbl_start_cycle) / bbl_nr_cycle;
            buf[0] = reinterpret_cast<void*>(addr);
            gperftools::update(buf.data(), buf.size());
            next_cycle += sample_nr_cycle;
        }
    } else {
        assert(gprof::samples)
        while (next_cycle < cur_cycle) {
            auto addr = ctx.m_cur_bbl->addr +
                ctx.m_cur_bbl->bytes * (next_cycle - m_bbl_start_cycle) / bbl_nr_cycle;
            gprof::update(addr);
            next_cycle += sample_nr_cycle;
        }
    }
    m_prev_cycle = next_cycle - sample_nr_cycle;
}

struct MemmapEntry {
    uintptr_t low, high;
    std::string file;

    MemmapEntry(uint64_t low_, uint64_t high_, const char *file_):
        low(low_), high(high_), file(file_)
    {}
};

void StackContext::print() const {
    std::vector<void*> bp;
    bp.push_back(reinterpret_cast<void*>(m_cur_bbl->addr));
    for (auto i = m_backtrace.crbegin(); i != m_backtrace.crend(); i ++)
        bp.push_back(reinterpret_cast<void*>(*i));
    print_backtrace(bp.data(), bp.size());
}

BblInfo StackContext::m_bbl_sentinel;

