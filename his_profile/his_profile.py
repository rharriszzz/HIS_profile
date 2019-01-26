# (c) Copyright Rocket Software, Inc. 2018, 2019 All Rights Reserved.

import os
import os.path
import sys
import struct
import bisect
import time
from datetime import datetime
import glob
import pickle
import itertools
import ctypes
from array import array
import traceback

from .control_his import run_his_test, get_map_for_asids
from ._csv_info import get_csv_info, get_module_info

command_verbose = True
CONSOLE_NAME="%sC" % os.getenv('USER')
ISSUE_COMMAND='issue_command'
DEFAULT_COMMAND_TIMEOUT=2

HIS_PATHNAME='/tmp/HIS_%s' % os.getenv("USER")
if not os.path.exists(HIS_PATHNAME):
    os.makedirs(HIS_PATHNAME)
    os.chown(HIS_PATHNAME, -1, os.getgid()) # change only the group

home_asid_set = {} # this is changed later

def MEM4(address, offset):
    return ctypes.c_int.from_address(address + offset).value

def MEM2(address, offset):
    return ctypes.c_short.from_address(address + offset).value

def get_current_ascb():
    PSAAOLD = 0x224
    return MEM4(0, PSAAOLD)

def get_current_asid():
    ASCBASID = 0x024
    return MEM2(get_current_ascb(), ASCBASID)

def decode_pointer4_to_char8_name(address, offset):
    name_address = MEM4(address, offset)
    if name_address == 0:
        return None
    else:
        name8e = ctypes.string_at(name_address, 8)
        return name8e.decode('cp1047').rstrip()
                                
def ascb_for_asid(asid):
    asvt = MEM4(MEM4(0, 0x10), 0x22C) # CVTASVT
    return MEM4(asvt, 0x20C + 4 * asid)

def jobname_for_asid(asid):
    if asid == 0x10000:
        return 'DAT-OFF'
    if asid < 1 or asid > 0xFFFF:
        return None
    ascb = ascb_for_asid(asid)
    name = decode_pointer4_to_char8_name(ascb, 0xAC)     # initiated jobname
    if name is None:
        name = decode_pointer4_to_char8_name(ascb, 0xB0) # started jobname
    return name

current_asid = get_current_asid()
home_asid_set = {current_asid}

def sorted_and_remove_duplicates(entries):
    entries = sorted(entries)
    new_entries = []
    last_entry = None
    for entry in entries:
        if last_entry != entry:
            new_entries.append(entry)
        last_entry = entry
    return new_entries

def best_name_for_info(info):
    for i in range(len(info) - 1, -1, -1):
        if info[i]:
            return info[i]
    return None

def show_entries(name):
    global entries
    print("--- %s ---" % name)
    for asid, address, is_begin, level, name in entries:
        print("%04X %016X %X %X %s" % (asid, address, is_begin, level, name))
    sys.stdout.flush()

import signal
def get_info_handler(signalnum, frame):
    pid = os.getpid()
    get_info_arguments_file = "/tmp/get_info_arguments_%d.pkl" % pid
    with open(get_info_arguments_file, "rb") as argfile:
        names = pickle.load(argfile)
    entries = list()
    get_csv_info(entries, get_current_asid())
    if names is not None:
        get_csv_info_entries = entries
        entries = list()
        for asid, address, is_begin, level, name in get_csv_info_entries:
            if is_begin == 1:
                begin_address = address
            else:
                end_address = address
            if name in names:
                get_module_info(entries, asid, name, begin_address, end_address)
    get_info_results_file = "/tmp/get_info_results_%d.pkl" % pid
    with open(get_info_results_file, "wb") as resultsfile:
        pickle.dump(entries, resultsfile)
    os.remove(get_info_arguments_file)

def install_info_on_sigusr1():
    signal.signal(signal.SIGUSR1, get_info_handler)

def get_info_for_process(pid, names):
    get_info_arguments_file = "/tmp/get_info_arguments_%d.pkl" % pid
    with open(get_info_arguments_file, "wb") as argfile:
        pickle.dump(names, argfile)
    os.kill(pid, signal.SIGUSR1)
    while os.path.isfile(get_info_arguments_file):
        time.sleep(0.1)
    get_info_results_file = "/tmp/get_info_results_%d.pkl" % pid
    with open(get_info_results_file, "rb") as resultsfile:
        entries = pickle.load(resultsfile)
    os.remove(get_info_results_file)
    return entries

def get_csv_info_for_current_asid():
    global entries, current_asid
    saved_entries = entries
    entries = list()
    for asid in (0, current_asid):
        get_csv_info(entries, asid)
    if False:
        show_entries("get_csv_info_for_current_asid")
    entries = saved_entries + entries

def get_module_info_for_current_asid():
    global entries, names_for_get_module_info, current_asid
    if False:
        print("names_for_get_module_info=%r" % (names_for_get_module_info,))
        sys.stdout.flush()
    saved_entries = entries
    entries = list()
    for asid in (0, current_asid):
        get_csv_info(entries, asid)
    get_csv_info_entries = entries
    entries = list()
    for asid, address, is_begin, level, name in get_csv_info_entries:
        if is_begin == 1:
            begin_address = address
        else:
            end_address = address
            if name in names_for_get_module_info:
                get_module_info(entries, asid, name, begin_address, end_address)
    if False:
        show_entries("get_module_info_for_current_asid")
    entries = saved_entries + entries
            
def add_entries_for_interval(asid, begin_address, end_address, level, interval, name):
    global entries
    saved_entries = entries
    entries = list()
    if (end_address - begin_address) / interval >= 2:
        split_name = name.split(':')
        name_without_addresses = split_name[0]
        parent_begin_offset = 0
        if len(split_name) == 3 and '(' not in split_name[1]:
            parent_begin_offset = int(split_name[1], 16)
        for begin_offset in range(0, end_address-begin_address, interval):
            begin_interval = begin_address + begin_offset
            end_interval = begin_interval + interval
            if end_interval > end_address:
                end_interval = end_address
            end_offset = end_interval - begin_address
            interval_name = "%s:+%X:+%X" % (split_name[0],
                                          parent_begin_offset+begin_offset, parent_begin_offset+end_offset)
            entries.append((asid, begin_interval,     1, level, interval_name))
            entries.append((asid, end_interval,       0, level, interval_name))
    if False:
        show_entries("add_entries_for_interval")
    entries = saved_entries + entries

pickled_his_map_filename = "profile_his_map_%s.pkl" % datetime.now().isoformat('-', 'seconds')

def get_maps_from_his(log=sys.stdout):
    global pickled_his_map_filename, current_asid, entries
    global private24, private31, primary_asid_to_jobname_map, primary_asid_to_count_map
    global sample_his_pathname_prefix
    if os.path.exists(pickled_his_map_filename):
        new_map = False
        with open(pickled_his_map_filename, "rb") as pickle_file:
            (entries, asids_mapped_by_his, private24, private31) = pickle.load(pickle_file)
    else:
        new_map = True
        entries = []
        entries.append((0x10000, 0,          1, 0, "DAT_OFF"))
        entries.append((0x10000, 0x7FFFFFFF, 0, 0, "DAT_OFF"))
        entries.append((0x10001, 0, 0, 0, ''))
        asids_mapped_by_his = set(())
    primary_asid_to_count_map = {}
    read_all_sample_files(sample_his_pathname_prefix, phase=0, log=log)
    total_count = sum([count for asid, count in primary_asid_to_count_map.items()])
    asid_threshold_count = total_count * 0.001
    asids_for_map = {asid for asid, count in primary_asid_to_count_map.items()
                     if count >= asid_threshold_count and asid < 0x10000}
    asids_for_map -= asids_mapped_by_his
    if new_map or asids_for_map:
        if not asids_for_map:
            asids_for_map = (current_asid)
        his_filename_prefix = get_map_for_asids(asids_for_map, log=log)
        asids_mapped_by_his |= asids_for_map
        his_map_pathname = HIS_PATHNAME + "/" + his_filename_prefix[0:-1] + '.000.MAP'
        read_his_map(his_map_pathname)
        if False:
            show_entries("his")
    with open(pickled_his_map_filename+".new", "wb") as pickle_his_map_file:
        pickle.dump((entries, asids_mapped_by_his, private24, private31),
                    pickle_his_map_file)
    os.rename(pickled_his_map_filename+".new", pickled_his_map_filename)
    return entries

def get_maps_and_analyze_samples(log=sys.stdout):
    global pickled_map_filename, current_asid, entries
    global private24, private31, primary_asid_to_jobname_map, primary_asid_to_count_map
    global names_for_get_module_info, names_for_interval_counting
    entries = get_maps_from_his(log=log)
    print("have %d entries from his" % (len(entries),))
    
    get_csv_info_for_current_asid()
    phase = 1
    print("have %d entries for phase %d" % (len(entries), phase))
    build_primaryasid_to_address_to_info_map()
    read_all_sample_files(sample_his_pathname_prefix, phase=1, log=log)
    total_count = sum([count for asid, count in primary_asid_to_count_map.items()])
    threshold_for_module_map = total_count * 0.001
    print("threshold_for_module_map=%d" % threshold_for_module_map)
    names_for_get_module_info = set(())
    for asid, (address_to_info_map, address_array, count_array) in primaryasid_to_address_to_info_map.items():
        for i in range(len(address_array)):
            begin_address = address_array[i]
            info = address_to_info_map[begin_address]
            count = count_array[i]
            name = best_name_for_info(info)
            if count > threshold_for_module_map:
                names_for_get_module_info.add(name)
    get_module_info_for_current_asid()
    for phase, interval, level in ((2, 4096, 7), (3, 16, 8)):
        print("have %d entries for phase %d, interval=%d, level=%d" % (len(entries), phase, interval, level))
        build_primaryasid_to_address_to_info_map()
        read_all_sample_files(sample_his_pathname_prefix, phase=phase, log=log)
        threshold_for_interval_map = total_count * 0.05
        names_for_interval_counting = set(())
        for asid, (address_to_info_map, address_array, count_array) in primaryasid_to_address_to_info_map.items():
            for i in range(len(address_array) - 1):
                begin_address = address_array[i]
                end_address = address_array[i+1]
                info = address_to_info_map[begin_address]
                count = count_array[i]
                if count > threshold_for_interval_map:
                    name = best_name_for_info(info)
                    if False:
                        print("## %04X %016X %016X len=%08X count=%06d %s" % (asid, begin_address, end_address,
                                                                              end_address - begin_address,
                                                                              count, name))
                    add_entries_for_interval(asid, begin_address, end_address, level, interval, name)
    phase = 4
    print("have %d entries for phase %d" % (len(entries), phase))
    build_primaryasid_to_address_to_info_map()
    read_all_sample_files(sample_his_pathname_prefix, phase=4, log=log)

# later: , home_asid_or_jobname_pattern_list=()
def run_test(name, fn, log=sys.stdout, jobnames=None):
    global test_name, test_fn, test_timestamp, sample_his_pathname_prefix
    global asid_to_name_map, primary_asid_to_jobname_map, primary_asid_to_count_map
    global names_for_get_module_info, names_for_interval_counting
    global private24, private31
    test_name = name
    test_fn = fn
    test_timestamp = datetime.now()
    his_filename_prefix = run_his_test(test_fn, log=log, jobnames=jobnames)
    sample_his_pathname_prefix = HIS_PATHNAME + "/" + his_filename_prefix
    primary_asid_to_jobname_map = {}
    asid_to_name_map = {}
    get_maps_and_analyze_samples(log=log)
    tree = build_count_tree()
    pickled_tree_filename = "profile_tree_%s.pkl" % datetime.now().isoformat('-', 'seconds')
    with open(pickled_tree_filename, "wb") as tree_pickle_file:
        pickle.dump(tree, tree_pickle_file)
    return pickled_tree_filename

def build_primaryasid_to_address_to_info_map():
    global entries, primaryasid_to_address_to_info_map, asid_to_name_map
    entries = sorted_and_remove_duplicates(entries)
    primaryasid_to_address_to_info_map = {}
    last_asid = None
    last_address = None
    for asid, address, is_begin, level, name in entries:
        if asid != last_asid:
            if last_asid is not None:
                address_to_info_list[1] = array("L", sorted(address_to_info_map.keys()))
                address_to_info_list[2] = array("I", itertools.repeat(0, len(address_to_info_list[1])))
            if asid == 0x10001:
                break
            last_asid = asid
            if asid_to_name_map and asid in asid_to_name_map:
                asid_name = asid_to_name_map[asid]
            else:
                asid_name = "%04X" % asid
            current_keys = [asid_name, None, None, None, None, None, None, None, None]
            if asid in primaryasid_to_address_to_info_map:
                address_to_info_list = primaryasid_to_address_to_info_map[asid]
                address_to_info_map = address_to_info_list[0]
            else:
                address_to_info_map = {}
                address_to_info_list = [address_to_info_map, None, None]
                primaryasid_to_address_to_info_map[asid] = address_to_info_list
            last_address = None
        if address != last_address:
            if last_address:
                address_to_info_map[last_address] = tuple(current_keys)
            last_address = address
        current_keys[level] = name if is_begin else None

def increment_count_for_asid_and_address(primary_asid, home_asid, address, increment=1, log=sys.stdout):
    global primaryasid_to_address_to_info_map
    if not primary_asid in primaryasid_to_address_to_info_map:
        print("No information for asid %04X, address=%016X" % (primary_asid, address), file=log)
        address_to_info_map = {0: ("?"), 0x7FFFFFFF: ("?")}
        address_to_info_list = [address_to_info_map, None, None]
        address_to_info_list[1] = array("L", sorted(address_to_info_map.keys()))
        address_to_info_list[2] = array("I", itertools.repeat(0, len(address_to_info_list[1])))
        #print(repr(address_to_info_list))
        primaryasid_to_address_to_info_map[primary_asid] = address_to_info_list
    address_to_info_map, address_array, count_array = primaryasid_to_address_to_info_map[primary_asid]
    if address_array is None:
        print("increment_count_for_asid_and_address: address_array is None for asid %04X" % (primary_asid,), file=log)
    index = bisect.bisect_right(address_array, address) - 1 # 'Find rightmost value less than or equal to x'
    if index < 0:
        print("increment_count_for_asid_and_address: bad index, asid=%04X, address=%016X" % (primary_asid, address), file=log)
    else:
        count_array[index] += increment

def read_his_map(his_map_pathname):
    global entries, private24, private31, asid_to_name_map
    encoding = None
    try:
        with open(his_map_pathname, "rt", encoding=encoding) as map_in:
            if 'I' != map_in.read(1):
                encoding = "cp1047_oe"
    except:
        encoding = "cp1047_oe"
    line_number = 0
    last_asid = None
    ModuleName = None
    with open(his_map_pathname, "rt", encoding=encoding) as map_in:
        while True:
            RecordType = map_in.read(1)
            if RecordType == '':
                return False
            line_number += 1
            MemoryArea = map_in.read(1) # N=Nucleus, M=MLPA, P=PLPA, F=FLPA, X=Private area, C=Common area
            Type_or_Asid = map_in.read(4)
            if MemoryArea == ' ':
                pass
            else:
                if MemoryArea == 'X':
                    asid = int(Type_or_Asid, 16)
                else:
                    asid = 0
                if asid != last_asid:
                    #print("read_his_map: asid=%04X" % (asid,))
                    last_asid = asid
            ShortName = map_in.read(8)
            if RecordType == 'I':
                map_in.readline()
            elif RecordType == 'A': # ShortName is the jobname
                asid_to_name_map[asid] = ShortName
                map_in.readline()
            else:
                begin_address = int(map_in.read(16), 16)
                if RecordType == 'E':
                    line = map_in.readline().rstrip()
                    name = ShortName
                    if len(line) > 0:
                        length_of_info_section = int(line[0:2], 16)
                        offset = int(line[2,6], 16) - 30
                        length = int(line[6,10], 16)
                        LongName = line[offset:offset+length]
                        name = "%s.%s" % (ShortName, LongName)
                    level = 3
                    entries.append((asid, begin_address, 1, level, name))
                else:
                    end_address = int(map_in.read(16), 16) + 1
                    if RecordType == 'B':
                        level = 0
                        name = "COMMON"
                        if ShortName == 'PRIVATE ':
                            private24 = (begin_address, end_address)
                            entries.append((0, 0,             1, level, name))
                            entries.append((0, begin_address, 0, level, name))
                            entries.append((0, end_address,   1, level, name))
                            entries.append((0, 0x01000000,    0, level, name))
                        elif ShortName == 'EPRV    ':
                            private31 = (begin_address, end_address)
                            entries.append((0, 0x01000000,    1, level, name))
                            entries.append((0, begin_address, 0, level, name))
                            entries.append((0, end_address,   1, level, name))
                            entries.append((0, 0x7FFFFFFF,    0, level, name))
                        map_in.readline()
                    else:
                        line = map_in.readline().rstrip()
                        name = ShortName
                        LongName = None
                        if len(line) > 0:
                            length_of_info_section = int(line[0:2], 16)
                            offset = int(line[2:6], 16) - 46
                            length = int(line[6:10], 16)
                            LongName = line[offset:offset+length]
                            if RecordType == 'C' or RecordType == 'S' or RecordType == 'F':
                                name = LongName
                            elif RecordType == 'M':
                                mtype = LongName[0]
                                if mtype == 'D':
                                    volser = LongName[1:7]
                                    dsn_length = int(LongName[7:9], 16)
                                    dsn = LongName[9:9+dsn_length]
                                    name = "%s:%s(%s)" % (volser, dsn, ShortName.rstrip())
                                elif mtype == 'C':
                                    pass # module is in the LPA
                                elif mtype == 'P':
                                    length = int(LongName[1:5], 16)
                                    name = LongName[5:5+length]
                        level = None
                        if RecordType == 'M':
                            level = 1
                            ModuleName = name
                        elif RecordType == 'C':
                            if LongName is None and '>' in ShortName:
                                pass
                            else:
                                level = 2
                                if ModuleName is None:
                                    if False:
                                        print("csect %s does not have a module" % (name,))
                                else:
                                    name = "%s:%s" % (ModuleName, name)
                        elif RecordType == 'S':
                            level = 4
                        elif RecordType == 'F':
                            level = 5
                        if level:
                            entries.append((asid, begin_address, 1, level, name))
                            entries.append((asid, end_address,   0, level, name))

def read_sample_file(sample_filename, phase, log=sys.stdout):
    global private24, private31, primary_asid_to_jobname_map, primary_asid_to_count_map
    total_samples = 0
    samples = 0
    with open(sample_filename, "rb") as samples_file:
        buffer_size = 4096 # can be configured to either be 4K or 1M
        block = bytearray(buffer_size)
        while buffer_size == samples_file.readinto(block):
            header_position = buffer_size - 64
            timestamp = block[header_position + 16 : header_position + 32]
            for position in range(0, header_position, 32):
                (format_code, number_of_unique_instructions, flags1, flags2, primary_asn, instruction_address,
                 tcb_or_web_address, home_asn, task_token) = struct.unpack_from("HBBHHL" "IHH", block, position)
                invalid = 0 != (flags1 & 0x01)
                dat_mode = 0 != (flags1 & 0x20)
                wait_state = 0 != (flags1 & 0x10)
                srb = 0 != (home_asn & 0x8000); home_asn &= 0x7FFF
                if not dat_mode:
                    primary_asn = 0x10000
                total_samples += 1
                if invalid or wait_state:
                    pass
                elif home_asn in home_asid_set:
                    samples += 1
                    problem_state = 0 != (flags1 & 0x08)
                    address_space_control = (flags1 & 0x06) >> 1 # if dat_mode: 0:primary, 1:ar, 2:secondary, 3:home
                    if phase == 0: # figure out which asids to ask his to map
                        if primary_asn not in primary_asid_to_jobname_map:
                            primary_asid_to_jobname_map[primary_asn] = jobname_for_asid(primary_asn)
                            primary_asid_to_count_map[primary_asn] = 1
                        else:
                            primary_asid_to_count_map[primary_asn] += 1
                    else:
                        private_bounds = private24 if instruction_address <= 0xFFFFFF else private31
                        is_private = private_bounds[0] <= instruction_address and instruction_address <= private_bounds[1]
                        if not is_private:
                            primary_asn = 0
                        wait = 0 != tcb_or_web_address & 0x80000000; tcb_or_web_address &= 0x7FFFFFFF
                        increment_count_for_asid_and_address(primary_asn, home_asn, instruction_address, log=log)
    return (samples, total_samples)

def read_all_sample_files(sample_prefix, phase, log=sys.stdout):
    if sample_prefix.endswith('.'):
        sample_prefix = sample_prefix[0:-1]
    count = 0
    for sample_filename in glob.glob("%s.000.SMP.*" % sample_prefix):
        count += 1
        samples, total_samples = read_sample_file(sample_filename, phase, log=log)
        if total_samples:
            print("%s samples=%s total=%d" % (sample_filename, samples, total_samples), file=log)
    return count

class count_tree:
    name = None
    count = 0
    key_to_subtree = None
    def __init__(self, name=()):
        self.name = name
        self.key_to_subtree = {}

    def add_count_to_tree(self, info_tuple, count, position=0):
        self.count += count
        while True:
            if position >= len(info_tuple):
                return
            current_name = info_tuple[position]
            if current_name is not None:
                break
            position += 1
        if current_name not in self.key_to_subtree:
            subtree_name = self.name + (current_name,)
            subtree = count_tree(subtree_name)
            self.key_to_subtree[current_name] = subtree
        else:
            subtree = self.key_to_subtree[current_name]
        subtree.add_count_to_tree(info_tuple, count, position+1)

def build_count_tree():
    tree = count_tree(())
    for asid, (address_to_info_map, address_array, count_array) in primaryasid_to_address_to_info_map.items():
        for i in range(len(address_array)):
            info = address_to_info_map[address_array[i]]
            count = count_array[i]
            if count > 0:
                tree.add_count_to_tree(info, count)
    return tree

def tree_item_count(tree_item):
    return tree_item[1].count

def print_tree(tree, total=None, indent = 0, threshold = 0.0025):
    if isinstance(tree, str):
        tree_pickle_filename = tree
        with open(tree_pickle_filename, "rb") as tree_pickle_file:
            tree = pickle.load(tree_pickle_file)
    if indent == 0:
        print("") 
        print("All rows are 1000*samples/total_samples (samples) name")
        print("threshold=%f" % threshold)
    if total is None:
        total = float(tree.count)
    item_list = tree.key_to_subtree.items()
    for key, subtree in sorted(item_list, key=tree_item_count, reverse=True):
        count = subtree.count
        fraction = count/total
        if fraction > threshold:
            print("%s %03d (%d) %s" % (' ' * indent, int(fraction*1000), count, key))
            print_tree(subtree, total, indent + 3, threshold)


