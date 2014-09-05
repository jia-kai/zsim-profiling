#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# $File: zprof.py
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
        def namelist():
            return name_list

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

    def merge_with(self, rhs):
        """merge rhs into self"""
        assert isinstance(rhs, CallEntry) and self.dest == rhs.dest
        self.cnt += rhs.cnt
        self.cost += rhs.cost


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

    def __str__(self):
        return 'RTN({}-{})'.format(mhex(self.begin), mhex(self.end))


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

    def _rm_overlap_rtn(self):
        # remove overlapped RTNs; I guess such overlapping is caused by
        # mishandling of RTN in PIN

        rtn_list = self.rtn_list
        nr_remove = 0
        idx = 1
        while idx < len(rtn_list):
            prev = rtn_list[idx - 1]
            cur = rtn_list[idx]
            is_sep = prev.end <= cur.begin
            is_contain = prev.begin <= cur.begin and prev.end >= cur.end
            assert is_sep ^ is_contain, \
                'disallowed RTN overlap: {}({}) {}({})'.format(
                    prev, self.addr2loc[prev.begin],
                    cur, self.addr2loc[cur.begin])
            if is_contain:
                nr_remove += 1
                del rtn_list[idx]
            else:
                idx += 1

        if nr_remove:
            logger.warn('removed {} overlapped RTN(s)'.format(nr_remove))

    def _build_func_prof(self):
        self._rm_overlap_rtn()
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
                idx0 = bbl_idx
                while self.bbl_list[bbl_idx].addr < rtn.begin:
                    assert self.bbl_list[bbl_idx].addr_last < rtn.begin, \
                        'BBL crosses RTN boundary'
                    bbl_idx += 1
                add(bbl_idx)
                while self.bbl_list[bbl_idx].addr < rtn.end:
                    assert self.bbl_list[bbl_idx].addr_last < rtn.end, \
                        'BBL crosses RTN boundary'
                    bbl_idx += 1
                add(bbl_idx)
                if idx0 == bbl_idx:
                    logger.warning('no bbl lies in {} ({})'.format(
                        rtn, self.addr2loc[rtn.begin]))
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
            assert len(set(j.dest for j in i.call_entry)) == len(i.call_entry)

        prev = self.bbl_list[0]
        for cur in self.bbl_list[1:]:
            if not (prev.addr < cur.addr and prev.addr_last <= cur.addr_last):
                logger.warn('BBL overlap: '
                            'prev_addr=[{}, {}] next_addr=[{}, {}]'.format(
                                mhex(prev.addr), mhex(prev.addr_last),
                                mhex(cur.addr), mhex(cur.addr_last)
                            ))
            prev = cur


    def _init_addr2loc(self, mem_map, basedir):
        addr = set()
        for i in self.bbl_list:
            addr.add(i.addr)
            addr.add(i.addr_last)
        for i in self.rtn_list:
            addr.add(i.begin)

        addr = sorted(addr)
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
            assert set(cur_addr) == set(result.keys())
            addr2loc.update(result)

        for cur in addr[addr_idx:-1]:
            addr2loc[cur] = AbsSourceLocation(cur, Unknown)

    def _addr2loc_onefile(self, obj_path, addr, mmap_begin, basedir):
        """:return: dict mapping from addr to AbsSourceLocation"""
        def relpath(fpath):
            if basedir and fpath.split('/')[:3] == basedir_start:
                fpath = os.path.relpath(fpath, basedir)
            return fpath

        NR_PATH_OVERLAP = 3
        if basedir:
            basedir_start = os.path.abspath(basedir).split('/')
            basedir_start = basedir_start[:NR_PATH_OVERLAP]

        if not addr:
            return dict()

        if '.so' in obj_path:
            # FIXME better way to test whether it is a relocatable shared obj
            addr = [i - mmap_begin for i in addr]
            addr_offset = mmap_begin
        else:
            addr_offset = 0

        addr_brief = addr[:2]
        if len(addr) == 3:
            addr_brief += addr[2]
        elif len(addr) > 3:
            addr_brief = map(mhex, addr_brief)
            addr_brief.append('<{} items>'.format(len(addr) - 3))
            addr_brief.append(mhex(addr[-1]))
        addr_brief_raw = addr_brief
        addr_brief = '[{}]'.format(', '.join(addr_brief))

        cmd = ['addr2line', '-afiCe', obj_path]
        obj_path = relpath(obj_path)
        cmd.extend(map(mhex, addr))

        logger.info('addr2line: {} in {}'.format(addr_brief, obj_path))
        if not os.path.exists(obj_path):
            logger.error('mapped object {} '
                         'does not exist on filesystem'.format(obj_path))
            return {i + addr_offset: AbsSourceLocation(i, Unknown)
                    for i in addr}

        subp = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        text_result = subp.communicate()[0]
        if subp.returncode:
            raise RuntimeError(
                'failed to execute addr2line: returncode={} cmd={}'.format(
                    subp.returncode, cmd[:-len(addr)] + addr_brief_raw))

        result = dict()

        text_result += '0x0'
        line_itr = iter(text_result.split('\n'))
        cur_loc = None
        for line in line_itr:
            if line.startswith('0x'):
                if cur_loc:
                    result[cur_addr + addr_offset] = cur_loc
                cur_addr = int(line[2:], 16)
                continue
            if not line:
                continue
            func = line
            src_path, lineno = next(line_itr).split(':')
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
            cur_loc = AbsSourceLocation(
                cur_addr, obj_path, src_path, func, lineno)


        for k, v in self._addr2loc_pltmap(obj_path).iteritems():
            k += addr_offset
            if k in result:
                v = AbsSourceLocation(k - addr_offset, obj_path, func=v)
                result[k] = v

        return result

    def _addr2loc_pltmap(self, obj_path):
        cmd = ['objdump', '-d', obj_path, '-j', '.plt']
        subp = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        text_result = subp.communicate()[0]
        if subp.returncode:
            raise RuntimeError('failed to execute {}: returncode={}'.format(
                cmd, subp.returncode))
        result = dict()
        for line in text_result.split('\n'):
            if 'Disassembly of section' in line or not line.endswith(':'):
                continue
            addr, func = line.split()
            addr = int(addr, 16)
            func = func[1:-2]
            if func.endswith('@plt-0x10'):
                func = 'plt[0]'
            result[addr] = func
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

        self._merge_bbl()
        self.addr2bbl = {i.addr: i for i in bbl_list}
        return mem_map


    def _merge_bbl(self):
        """merge call to other functions if two BBLs share the same end addr"""
        bbl_list = self.bbl_list
        bbl_list.sort(key=lambda x: (x.addr, x.addr_last))

        nr_merge = 0
        idx = 1
        while idx < len(bbl_list):
            prev = bbl_list[idx - 1]
            cur = bbl_list[idx]
            if prev.addr == cur.addr and prev.addr_last == cur.addr_last:
                nr_merge += 1
                cur.nr_hit += prev.nr_hit
                cur.self_cost += prev.self_cost
                cur_dest2ent = {i.dest: i for i in cur.call_entry}
                for pent in prev.call_entry:
                    cent = cur_dest2ent.get(pent.dest)
                    if cent:
                        cent.merge_with(pent)
                    else:
                        cur.call_entry.append(pent)
                del bbl_list[idx - 1]
            else:
                idx += 1

        if nr_merge:
            logger.warn('{} identical BBL pairs are merged'.format(nr_merge))

        nr_merge = 0
        prev = bbl_list[0]
        for cur in bbl_list[1:]:
            prev_dest2ent = {i.dest: i for i in prev.call_entry}
            if prev.addr_last == cur.addr_last:
                for i in cur.call_entry:
                    pent = prev_dest2ent.get(i.dest)
                    if pent:
                        i.merge_with(pent)
                        found = False
                        for idx, p in enumerate(prev.call_entry):
                            if p.dest == i.dest:
                                found = True
                                del prev.call_entry[idx]
                                break
                        assert found
                        nr_merge += 1

            prev = cur

        if nr_merge:
            logger.warn('{} pairs of calls with same '
                        'ending address are merged'.format(nr_merge))


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

def print_bbl_detail(prof_rst, addr):
    addr = int(addr, 16)
    sys.stdout.write(hex(addr) + ':\n')
    entry = prof_rst.addr2bbl.get(addr)
    if not entry:
        sys.stdout.write('  not found\n')
        return
    write = lambda k, v: sys.stdout.write('  {}={}\n'.format(k, v))
    write('addr_last', mhex(entry.addr_last))
    write('loc', prof_rst.addr2loc[addr])
    write('nr_hit', entry.nr_hit)
    cost = entry.self_cost
    for name in cost.namelist():
        write('cost::' + name, getattr(cost, name))
    for call in entry.call_entry:
        sys.stdout.write('  call: dest={} cnt={}\n'.format(mhex(call.dest), call.cnt))

def work(args):
    prof_rst = ProfileResult(args)

    if args.top:
        show_top(prof_rst, args)

    if args.callgrind:
        convert_callgrind(prof_rst, args)

    if args.bbl:
        for addr in args.bbl:
            print_bbl_detail(prof_rst, addr)

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
    parser.add_argument('--bbl', action='append',
                        help='addr of BBLs whose detailed stat would be printed')
    parser.add_argument('input', help='zsim profile')
    args = parser.parse_args()
    work(args)



class LogFormatter(logging.Formatter):
    def format(self, record):
        date = '\x1b[32m[%(asctime)s.%(msecs)03d]\x1b[0m'
        msg = '%(message)s'
        if record.levelno == logging.WARNING:
            fmt = '{} \x1b[1;31mWRN\x1b[0m {}'.format(date, msg)
        elif record.levelno == logging.ERROR:
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
