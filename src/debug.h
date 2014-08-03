/** $lic$
 * Copyright (C) 2012-2014 by Massachusetts Institute of Technology
 * Copyright (C) 2010-2013 by The Board of Trustees of Stanford University
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

#ifndef DEBUG_H_
#define DEBUG_H_

#include <cstddef>
#include <functional>

//This header has common debugging datastructure defs.

/* Describes the addresses at which libzsim.so is loaded. GDB needs this. */
struct LibInfo {
    void* textAddr;
    void* bssAddr;
    void* dataAddr;
};

void print_backtrace(const void * const *stack, int depth);

void print_backtrace_zsim();

/*!
 * print backtrace of the simulated program
 * \param tid thread id, or -1 for current thread
 */
void print_backtrace_app(int tid = -1);

/*!
 * get memory map of a process
 * \param pid process id, 0 for self
 * \param callback callback function, which takes (begin, end, perm, filepath) *
 *      arguments
 */
void get_mem_map(int pid, std::function<void(uintptr_t, uintptr_t, const char *, const char*)> callback);

#endif  // DEBUG_H_
