#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# $File: zprof.py
# $Date: Tue Aug 05 16:31:32 2014 -0700
# $Author: jiakai <jia.kai66@gmail.com>

from ctypes import Structure, c_uint64
import struct
import argparse
import logging
import subprocess
import os
import sys
import weakref
logger = logging.getLogger(__name__)

ZSIM_PROF_MAGIC = 'zsimprof'

def mhex(v):
    v = hex(v)
    if v[-1] == 'L':
        v = v[:-1]
    return v

class Unknown(object):
    def __sub__(self, rhs):
        return self

    def __eq__(self, rhs):
        return False

    def __ne__(self, rhs):
        return True

    def __str__(self):
        return '??'

    __repr__ = __str__

Unknown = Unknown()

def make_cost_class(name_list):
    """create a class to represent profile cost"""
    class Cost(Structure):
        _fields_ = [(i, c_uint64) for i in name_list]

        def __add__(self, rhs):
            rst = Cost()
            for i in name_list:
                val = getattr(self, i) + getattr(rhs, i)
                setattr(rst, i, val)
            return rst

        def __str__(self):
            return 'Cost({})'.format(', '.join(
                '{}={}'.format(k, getattr(self, k))
                for k in name_list))

        def raw_str(self):
            return ' '.join([str(getattr(self, i)) for i in name_list])

        @staticmethod
        def namelist_str():
            return ' '.join(name_list)

    return Cost


class AbsSourceLocation(object):
    __slots__ = ['addr', 'obj_path', 'src_path', 'func', 'line']

    def __init__(self, addr, obj_path,
                 src_path=Unknown, func=Unknown, line=Unknown):
        if func is Unknown:
            func = mhex(addr)
        self.addr = addr
        self.obj_path = obj_path
        self.src_path = src_path
        self.func = func
        self.line = line

    @property
    def func_id(self):
        """unique identifier defining a function"""
        if self.src_path is Unknown or self.func is Unknown:
            return Unknown
        return (self.src_path, self.func)

    def __str__(self):
        return '{} at {}:{} <{}:{}>'.format(
            self.func, self.src_path, self.line,
            self.obj_path, mhex(self.addr))

    def __repr__(self):
        return 'AbsSourceLocation({})'.format(str(self))


class BBLEntry(Structure):
    _fields_ = [('addr', c_uint64),
                ('addr_last', c_uint64),
                ('nr_hit', c_uint64)]

    self_cost = None
    """instance of class returned by :meth:`make_cost_class`"""

    call_entry = None
    """list of :class:`CallEntry` objects"""

    loc = None
    """:class:`AbsSourceLocation` object"""

    func_prof = None
    """weak reference to :class:`FuncProf`"""


class CallEntry(Structure):
    _fields_ = [('dest', c_uint64),
                ('cnt', c_uint64)]

    cost = None
    """instance of class returned by :meth:`make_cost_class`"""


class MemMapEntry(Structure):
    _fields_ = [('begin', c_uint64), ('end', c_uint64)]
    path = None

    def __str__(self):
        return '[{}-{}] {}'.format(mhex(self.begin), mhex(self.end), self.path)

class RTNEntry(Structure):
    _fields_ = [('begin', c_uint64), ('size', c_uint64)]

    @property
    def end(self):
        return self.begin + self.size


class FuncProf(object):
    bbl_list = None
    """list of :class:`BBLEntry`"""

    self_cost = None

    def __init__(self, bbl_list):
        """:param bbl_list: list of :class:`BBLEntry`"""
        assert isinstance(bbl_list, list) and len(bbl_list) > 0
        bbl_list = bbl_list[:]
        self.bbl_list = bbl_list
        self.self_cost = sum([i.self_cost for i in bbl_list[1:]],
                             bbl_list[0].self_cost)

        ref_self = weakref.proxy(self)
        for i in bbl_list:
            i.func_prof = ref_self

        self._merge_out_call()

    def _merge_out_call(self):
        prev = self.bbl_list[0]
        for cur in self.bbl_list[1:]:
            prev_dest2ent = {i.dest: i for i in prev.call_entry}
            for i in cur.call_entry:
                pent = prev_dest2ent.get(i.dest)
                if pent:
                    i.cnt += pent.cnt
                    i.cost += pent.cost
                    found = False
                    for idx, p in enumerate(prev.call_entry):
                        if p.dest == i.dest:
                            found = True
                            del prev.call_entry[idx]
                            break
                    assert found

            prev = cur

    @property
    def nr_call(self):
        return self.bbl_list[0].nr_hit

    @property
    def loc(self):
        return self.bbl_list[0].loc

    @property
    def avg_self_cycle(self):
        return float(self.self_cost.cycle) / self.nr_call


class ProfileResult(object):
    bbl_list = None
    """list of :class:`BBLEntry`"""

    addr2loc = None
    """dict: addr => :class:`SourceLocation` object"""

    addr2bbl = None
    """dict: addr => :class:`BBLEntry` object"""

    func_prof = None
    """list of :class: `FuncProf`"""

    func_entry_addr = None
    """set of all call destinations"""

    rtn_list = None
    """list of :class:`RTNEntry`"""

    def __init__(self, args):
        mem_map = self._load_data(args.input)
        self._init_addr2loc(mem_map, args.basedir)
        for i in self.bbl_list:
            i.loc = self.addr2loc[i.addr]
        self._build_func_prof()
        self._check()

        # self._dump()

    def _dump(self):
        for i in self.func_prof:
            sys.stdout.write('function: {}\n'.format(i.loc.func))
        for i in self.bbl_list:
            if not i.call_entry:
                continue
            src = self.addr2loc[i.addr_last]
            for j in i.call_entry:
                dest = self.addr2loc[j.dest]
                sys.stdout.write('call {}({})=>{}({}): cnt={} cyc={}\n'.format(
                    src.func, mhex(src.addr),
                    dest.func, mhex(dest.addr), j.cnt, j.cost.cycle))

    def _build_func_prof(self):
        logger.info('building profiling result for each function ...')
        self.bbl_list.sort(key=lambda i: i.addr)
        self.func_entry_addr = set()
        for i in self.bbl_list:
            self.func_entry_addr.update([j.dest for j in i.call_entry])


        self.func_prof = func_prof = list()

        def add(idx):
            if add.idx_end < idx:
                func_prof.append(FuncProf(self.bbl_list[add.idx_end:idx]))
                add.idx_end = idx
        add.idx_end = 0

        bbl_idx = 0
        try:
            for rtn in self.rtn_list:
                while self.bbl_list[bbl_idx].addr < rtn.begin:
                    bbl_idx += 1
                add(bbl_idx)
                while self.bbl_list[bbl_idx].addr < rtn.end:
                    bbl_idx += 1
                add(bbl_idx)
        except IndexError:
            pass
        add(len(self.bbl_list))

        logger.info('found {} functions (rtns={})'.format(
            len(func_prof), len(self.rtn_list)))

    def _check(self):
        for i in self.bbl_list:
            assert i.addr in self.addr2loc
            assert i.func_prof, i.loc
            if i.call_entry:
                assert i.addr_last in self.addr2loc
            for j in i.call_entry:
                assert j.dest in self.addr2bbl
                assert j.dest in self.addr2loc

    def _init_addr2loc(self, mem_map, basedir):
        addr = list()
        for i in self.bbl_list:
            addr.append(i.addr)
            addr.append(i.addr_last)

        addr.sort()
        mem_map = sorted(mem_map, key=lambda i: i.begin)

        addr.append(max(addr[-1], mem_map[-1].end) + 1)

        self.addr2loc = addr2loc = dict()
        addr_idx = 0

        for ment in mem_map:
            while addr[addr_idx] < ment.begin:
                cur = addr[addr_idx]
                addr2loc[cur] = AbsSourceLocation(cur, Unknown)
                addr_idx += 1

            addr_idx_begin = addr_idx
            while addr[addr_idx] < ment.end:
                addr_idx += 1

            cur_addr = addr[addr_idx_begin:addr_idx]
            result = self._addr2loc_onefile(
                ment.path, cur_addr, ment.begin, basedir)
            assert len(cur_addr) == len(result)
            addr2loc.update(zip(cur_addr, result))

        for cur in addr[addr_idx:-1]:
            addr2loc[cur] = AbsSourceLocation(cur, Unknown)

    def _addr2loc_onefile(self, obj_path, addr, mmap_begin, basedir):
        def relpath(fpath):
            if basedir and fpath.split('/')[:3] == basedir_start:
                fpath = os.path.relpath(fpath, basedir)
            return fpath

        NR_PATH_OVERLAP = 3
        if basedir:
            basedir_start = os.path.abspath(basedir).split('/')
            basedir_start = basedir_start[:NR_PATH_OVERLAP]

        if not addr:
            return []

        if '.so' in obj_path:
            # FIXME better way to test whether it is a relocatable shared obj
            addr = [i - mmap_begin for i in addr]

        addr_brief = addr[:2]
        if len(addr) == 3:
            addr_brief += addr[2]
        elif len(addr) > 3:
            addr_brief = map(mhex, addr_brief)
            addr_brief.append('<{} items>'.format(len(addr) - 3))
            addr_brief.append(mhex(addr[-1]))
        addr_brief_raw = addr_brief
        addr_brief = '[{}]'.format(', '.join(addr_brief))

        cmd = ['addr2line', '-f', '-C', '-e', obj_path]
        obj_path = relpath(obj_path)
        cmd.extend(map(mhex, addr))

        logger.info('addr2line: {} in {}'.format(addr_brief, obj_path))
        if not os.path.exists(obj_path):
            logger.error('mapped object {} '
                         'does not exist on filesystem'.format(obj_path))
            return [AbsSourceLocation(i, Unknown) for i in addr]

        subp = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        text_result = subp.communicate()[0]
        if subp.returncode:
            raise RuntimeError(
                'failed to execute addr2line: returncode={} cmd={}'.format(
                    subp.returncode, cmd[:-len(addr)] + addr_brief_raw))
        lines = text_result.split('\n')[:-1]
        assert len(lines) == len(addr) * 2
        result = []
        for idx in xrange(len(addr)):
            func = lines[idx * 2]
            src_path, lineno = lines[idx * 2 + 1].split(':')
            if func == '??' or not func:
                func = Unknown
            if src_path == '??' or not src_path:
                src_path = Unknown
            else:
                src_path = relpath(src_path)
            if 'discriminator' in lineno:
                lineno = lineno.split(' ')[0]
            try:
                lineno = int(lineno)
                if lineno == 0:
                    lineno = Unknown
            except ValueError:
                lineno = Unknown

            result.append(AbsSourceLocation(
                addr[idx], obj_path, src_path, func, lineno))

        return result
    
    def _load_data(self, fpath):
        """:return: memory map list"""
        def readobj(t, costattr=None):
            v = t()
            # undocumented but usable on python 2.7
            fin.readinto(v)
            if costattr:
                setattr(v, costattr, readcost())
            return v

        def readstr():
            v = list()
            while True:
                ch = fin.read(1)
                if ch == '\x00':
                    break
                v.append(ch)
            return ''.join(v)

        readint = lambda: readobj(c_uint64).value
        readcost = lambda: readobj(Cost)

        with open(fpath) as fin:
            magic = fin.read(len(ZSIM_PROF_MAGIC))
            assert magic == ZSIM_PROF_MAGIC, 'bad file format'
            logger.info('Loading profiling stats ...')

            nr_cost = readint()
            cost_name_list = [readstr() for _ in xrange(nr_cost)]
            Cost = make_cost_class(cost_name_list)

            nr_bbl_list = readint()
            self.bbl_list = bbl_list = list()
            for _ in xrange(nr_bbl_list):
                cur = readobj(BBLEntry, 'self_cost')
                nr_call_entry = readint()
                cur.call_entry = [readobj(CallEntry, 'cost')
                                  for _ in range(nr_call_entry)]
                bbl_list.append(cur)

            self.addr2bbl = {i.addr: i for i in bbl_list}

            logger.info('{} BBL entries loaded'.format(nr_bbl_list))

            nr_rtn = readint()
            self.rtn_list = [readobj(RTNEntry) for _ in xrange(nr_rtn)]
            self.rtn_list.sort(key=lambda x: x.begin)

            nr_map = readint()
            mem_map = list()
            for _ in xrange(nr_map):
                cur = readobj(MemMapEntry)
                cur.path = readstr()
                mem_map.append(cur)

            return mem_map

def show_top(prof_rst, args):
    frst = sorted(prof_rst.func_prof, key=lambda i: -i.self_cost.cycle)[:args.topn]

    for idx, ent in enumerate(frst):
        sys.stdout.write('======= top {}: cycles={} calls={} avg={:.2f}\n'.format(
            idx, ent.self_cost.cycle, ent.nr_call, ent.avg_self_cycle))
        sys.stdout.write('  {}\n'.format(ent.loc))


class CallgrindWriter(object):
    """write callgrind file
    see http://valgrind.org/docs/manual/cl-format.html"""

    func_prof = None
    addr2loc = None

    class PositionSpec(object):
        def __init__(self, name, write,
                     dedup=lambda self, val: self._prev_val == val,
                     val_map=None):
            if val_map is None:
                val_map = dict()
            self._name = name
            self._write = write
            self._prev_val = None
            self._val_map = val_map
            self._dedup = dedup

        def __call__(self, val):
            val = str(val)
            if self._dedup(self, val):
                return
            self._prev_val = val
            vid = self._val_map.get(val)
            if vid is None:
                vid = len(self._val_map) + 1
                self._val_map[val] = vid
                self._write('{}=({}) {}'.format(self._name, vid, val))
            else:
                self._write('{}=({})'.format(self._name, vid))
            return True

        def force_write(self):
            self._write('{}=({})'.format(
                self._name, self._val_map[self._prev_val]))
            

    def __init__(self, prof_rst):
        self.func_prof = prof_rst.func_prof
        self.addr2loc = prof_rst.addr2loc
        self.addr2bbl = prof_rst.addr2bbl

    def _wrline(self, *args):
        """write a line"""
        s = ' '.join(map(str, args))
        self._fout.write(s + '\n')

    def write(self, fout):
        try:
            self._fout = fout
            self._ps_obj = self.PositionSpec('ob', self._wrline)
            self._ps_src = self.PositionSpec('fl', self._wrline)
            self._ps_func = self.PositionSpec('fn', self._wrline)
            self._ps_callee_obj = self.PositionSpec(
                'cob', self._wrline,
                lambda _, val: val == self._ps_obj._prev_val,
                self._ps_obj._val_map)
            self._ps_callee_src = self.PositionSpec(
                'cfi', self._wrline,
                lambda _, val: val == self._ps_src._prev_val,
                self._ps_src._val_map)
            self._ps_callee_func = self.PositionSpec(
                'cfn', self._wrline,
                lambda _, __: False,
                self._ps_func._val_map)
            self._work()
        finally:
            del self._fout
            del self._ps_obj
            del self._ps_src
            del self._ps_func
            del self._ps_callee_obj
            del self._ps_callee_src
            del self._ps_callee_func

    def _work(self):
        self._wrline('creator: zsim profiler')
        self._wrline('positions: instr line')
        self._wrline('events: {}'.format(
            self.func_prof[0].bbl_list[0].self_cost.namelist_str()))
        for func in self.func_prof:
            loc = func.loc
            a = self._ps_obj(loc.obj_path)
            b = self._ps_src(loc.src_path)
            c = self._ps_func(loc.func)
            if a or b or c:
                ref_loc = None
            if a:
                if not b:
                    self._ps_src.force_write()
                if not c:
                    self._ps_func.force_write()
            for bbl in func.bbl_list:
                instr, line = self._get_subposition(ref_loc, bbl.loc)
                self._wrline(instr, line, bbl.self_cost.raw_str())
                ref_loc = bbl.loc
                for call in bbl.call_entry:
                    ref_loc = None
                    src = self.addr2loc[bbl.addr_last]
                    dest = self.addr2bbl[call.dest].func_prof.loc
                    self._ps_callee_obj(dest.obj_path)
                    self._ps_callee_src(dest.src_path)
                    self._ps_callee_func(dest.func)
                    self._wrline('calls={} {} {}'.format(
                        call.cnt, mhex(dest.addr),
                        0 if dest.line is Unknown else dest.line))
                    instr, line = self._get_subposition(ref_loc, src)
                    self._wrline(instr, line, call.cost.raw_str())

    @staticmethod
    def _get_subposition(ref_loc, loc):
        def rela(v):
            if v == 0:
                return '*'
            if v > 0:
                return '+{}'.format(v)
            return '-{}'.format(v)

        instr = loc.addr
        line = loc.line
        if ref_loc is not None:
            instr = rela(instr - ref_loc.addr)
            if ref_loc.line is not Unknown and line is not Unknown:
                line = rela(line - ref_loc.line)
        else:
            instr = mhex(instr)
        if line is Unknown:
            line = '*' if ref_loc else 0

        return instr, line

def convert_callgrind(prof_rst, args):
    assert args.output, 'must specify output file (see -o option)'
    writer = CallgrindWriter(prof_rst)
    with open(args.output, 'w') as fout:
        writer.write(fout)

def work(args):
    prof_rst = ProfileResult(args)
    if args.top:
        show_top(prof_rst, args)
    if args.callgrind:
        convert_callgrind(prof_rst, args)


def main():
    parser = argparse.ArgumentParser(
        description='Convert zsim profile result into callgrind format',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-b', '--basedir',
                        help='directory based on to convert '
                        'source file path to relative path')
    parser.add_argument('-o', '--output', help='output file')
    parser.add_argument('--top', action='store_true',
                        help='show functions that consume most of the time')
    parser.add_argument('--callgrind', action='store_true',
                        help='output in callgrind file format')
    parser.add_argument('--topn', type=int, default=10,
                        help='number of fuctions to show')
    parser.add_argument('input', help='zsim profile')
    args = parser.parse_args()
    work(args)



class LogFormatter(logging.Formatter):
    def format(self, record):
        date = '\x1b[32m[%(asctime)s.%(msecs)03d]\x1b[0m'
        msg = '%(message)s'
        if record.levelno == logging.ERROR:
            fmt = '{} \x1b[1;4;31mERR\x1b[0m {}'.format(date, msg)
        else:
            fmt = date + ' ' + msg
        self._fmt = fmt
        return super(LogFormatter, self).format(record)

def setup_logging():
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setFormatter(LogFormatter(datefmt='%H:%M:%S'))
    ch.setLevel(logging.DEBUG)
    logger.addHandler(ch)

if __name__ == '__main__':
    setup_logging()
    main()
