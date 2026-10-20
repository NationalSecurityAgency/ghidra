/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// Code is derived from work done by https://github.com/gaasedelen/tenet under the MIT license

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "pin.H"

using std::ofstream;

#ifdef __i386__
constexpr auto PC = "eip";
#else
constexpr auto PC = "rip";
#endif

#if defined(TARGET_WINDOWS)
constexpr char PATH_SEPARATOR = '\\';
#else
constexpr char PATH_SEPARATOR = '/';
#endif

static KNOB<std::string> KnobModuleWhitelist(
    KNOB_MODE_APPEND, "pintool", "w", "",
    "Add a module to the whitelist. If none is specified, every module is "
    "white-listed. Example: calc.exe");

static KNOB<std::string> KnobOutputFilePrefix(
    KNOB_MODE_WRITEONCE, "pintool", "o", "trace",
    "Prefix of the output .trace file.");

static KNOB<std::string> KnobStartAt(
    KNOB_MODE_APPEND, "pintool", "s", "",
    "Start tracing when an image:offset is hit.\nExample: -s "
    "kernel32.dll:1234 -s app:2FFF");

static KNOB<std::string> KnobStopAt(
    KNOB_MODE_APPEND, "pintool", "e", "",
    "Stop tracing when an image:offset is hit.\nExample: -e "
    "kernel32.dll:1234 -e app:2FFF");

static KNOB<int> KnobTraceGranularity(
    KNOB_MODE_WRITEONCE, "pintool", "g", "2",
    "Trace granularity level:\n2=Instruction Level Tracing\n4=Basic Block "
    "Level Tracing\n8=Routine Level Tracing");

static KNOB<BOOL> KnobCollectMem(KNOB_MODE_WRITEONCE, "pintool",
                                 "rec_all_memory", "0",
                                 "Record all memory r/w events regardless of "
                                 "granularity level until next log write");


static std::string base_name(const std::string &path) {
    const std::string::size_type idx = path.rfind(PATH_SEPARATOR);
    std::string name = (idx == std::string::npos) ? path : path.substr(idx + 1);
    return name;
}

namespace {
    struct Image {
        std::string name_;
        ADDRINT low_;
        ADDRINT high_;

        explicit Image(std::string n = "", const ADDRINT low = 0, const ADDRINT high = 0)
            : name_(std::move(n)), low_(low), high_(high) {
        }

        // Overloaded method to implement searches over the loaded images list
        // and also allow this class to be used on a set like STL container.
        bool operator<(const Image &rhs) const { return low_ < rhs.low_; }
    };

    class ImageManager {
        // Set of module names that are allowed to be traced.
        std::set<Image> images;
        PIN_RWMUTEX images_lock{};

        // Here we store the names of the images inside our white list.
        std::set<std::string, std::less<> > whitelist;

        // Store the last recently matched image so we can use it as a cache.
        ADDRINT cached_low{};
        ADDRINT cached_high{};

    public:
        ImageManager() { PIN_RWMutexInit(&images_lock); }

        virtual ~ImageManager() { PIN_RWMutexFini(&images_lock); }

        VOID addWhiteListedImage(const std::string &image_name) {
            whitelist.insert(image_name);
        }

        BOOL isWhiteListed(const std::string &image_name) {
            return whitelist.find(image_name) != whitelist.end();
        }

        BOOL isInterestingAddress(ADDRINT addr) {
            PIN_RWMutexReadLock(&images_lock);
            {
                // If there is no white-listed image, everything is white-listed.
                if ((images.empty() && whitelist.empty()) ||
                    (addr >= cached_low && addr < cached_high)) {
                    PIN_RWMutexUnlock(&images_lock);
                    return true;
                }

                auto i = images.upper_bound(Image("", addr));
                if (i == images.begin()) {
                    PIN_RWMutexUnlock(&images_lock);
                    return false;
                }
                --i;

                // If the instruction address does not fall inside a valid white listed
                // image, bail out.
                if (!(i != images.end() && i->low_ <= addr && addr < i->high_)) {
                    PIN_RWMutexUnlock(&images_lock);
                    return false;
                }

                // Save the matched image.
                cached_low = i->low_;
                cached_high = i->high_;
            }
            PIN_RWMutexUnlock(&images_lock);

            return true;
        }

        VOID addImage(std::string image_name, ADDRINT lo_addr, ADDRINT hi_addr) {
            PIN_RWMutexWriteLock(&images_lock);
            {
                images.emplace(std::move(image_name), lo_addr, hi_addr);
            }
            PIN_RWMutexUnlock(&images_lock);
        }

        VOID removeImage(const ADDRINT low) {
            PIN_RWMutexWriteLock(&images_lock);
            {
                if (const auto i = images.find(Image("", low)); i != images.end()) {
                    images.erase(i);
                }
            }
            PIN_RWMutexUnlock(&images_lock);
        }
    };

    struct ThreadData {
        std::array<ADDRINT, REG_GR_LAST + 1> m_cpu{};

        ADDRINT mem_w_addr{};
        ADDRINT mem_w_size{};
        ADDRINT mem_r_addr{};
        ADDRINT mem_r_size{};
        ADDRINT mem_r2_addr{};
        ADDRINT mem_r2_size{};

        ADDRINT largestSize = 0;

        struct MemEvent {
            ADDRINT addr = 0;
            UINT32 size = 0;
            uint8_t access_flags = 0;

            ADDRINT end() const { return addr + size; }
        };

        std::map<ADDRINT, MemEvent> mem_events;
    };

    enum class TraceGranularity : int {
        TRACE_INSTRUCTION = 2,
        TRACE_BASIC_BLOCK = 4,
        TRACE_ROUTINE = 8,
    };

    class ToolContext {
    public:
        explicit ToolContext(const std::string &log_name) {
            PIN_InitLock(&write_lock);

            tls_key = PIN_CreateThreadDataKey(nullptr);
            trace_file = ofstream(log_name.c_str());
            trace_file << std::hex;
        }

        ~ToolContext() {
            trace_file.close();
        }

        ThreadData *GetThreadLocalData(const THREADID tid) const {
            return static_cast<ThreadData *>(PIN_GetThreadData(tls_key, tid));
        }

        void setThreadLocalData(const THREADID tid, const ThreadData *data) const {
            PIN_SetThreadData(tls_key, data, tid);
        }

        std::ofstream trace_file;
        std::unique_ptr<ImageManager> image_manager;

        std::vector<std::pair<std::string, ADDRINT> > pending_start_specs;
        std::vector<ADDRINT> start_addrs;

        std::vector<std::pair<std::string, ADDRINT> > pending_stop_specs;
        std::vector<ADDRINT> stop_addrs;

        bool wait_for_start = false;
        bool start_and_end_defined = false;

        PIN_LOCK write_lock{};

        bool tracing_enabled = true;

        TLS_KEY tls_key;
    };
}

static BOOL should_trace(ToolContext *context, const ADDRINT pc) {
    const BOOL interestingAddress = context->image_manager->isInterestingAddress(pc);
    if (context->start_and_end_defined) {
        BOOL pending_disable_tracing = false;
        if (context->wait_for_start) {
            for (const ADDRINT tgt: context->start_addrs) {
                if (pc == tgt) {
                    context->tracing_enabled = true;
                    context->wait_for_start = false;
                    LOG("Start address hit: 0x" + hexstr(tgt) + ", enabling tracing\n");
                    break;
                }
            }
        } else {
            context->tracing_enabled = interestingAddress;
            for (const ADDRINT tgt: context->stop_addrs) {
                if (pc == tgt) {
                    context->tracing_enabled = false;
                    pending_disable_tracing = true;
                    context->wait_for_start = true;
                    LOG("Stop address hit: 0x" + hexstr(tgt) + ", disabling tracing\n");
                    break;
                }
            }
        }

        if (pending_disable_tracing) {
            context->tracing_enabled = false;
        } else if (!context->tracing_enabled) {
            return false;
        }
        return interestingAddress;
    }
    return interestingAddress;
}

static void add_mem_event(ThreadData *data, const ADDRINT addr, const UINT32 size,
                          const uint8_t flags) {
    if (size == 0) return;

    ADDRINT newEnd = addr + size;
    ADDRINT newStart = addr;
    UINT8 newFlags = flags;

    auto it = data->mem_events.lower_bound(newStart);
    if (it != data->mem_events.begin()) {
        if (const auto prev = std::prev(it); prev->second.end() >= newStart) {
            newStart = prev->first;
            newEnd = std::max(newEnd, prev->second.end());
            newFlags |= prev->second.access_flags;
            data->mem_events.erase(prev);
        }
    }

    while (it != data->mem_events.end() && it->first <= newEnd) {
        newFlags |= it->second.access_flags;
        newEnd = std::max(newEnd, it->second.end());
        it = data->mem_events.erase(it);
    }

    const auto newSize = static_cast<UINT32>(newEnd - newStart);
    if (newSize > data->largestSize) data->largestSize = newSize;
    data->mem_events[newStart] = {.addr = newStart, .size = newSize, .access_flags = newFlags};
}

static VOID on_thread_start(const THREADID tid, CONTEXT *ctxt, INT32 flags, VOID *v) {
    const auto &context = *static_cast<ToolContext *>(v);
    const auto *data = new ThreadData();
    context.setThreadLocalData(tid, data);
}

static VOID on_image_load(const IMG img, VOID *v) {
    auto &context = *static_cast<ToolContext *>(v);
    const std::string img_name = base_name(IMG_Name(img));

    if (IMG_IsVDSO(img)) {
        return;
    }

    const ADDRINT low = IMG_LowAddress(img);
    const ADDRINT high = IMG_HighAddress(img);
    const size_t size = high - low;


    std::vector<unsigned char> tmp(size);
    unsigned char *buf = nullptr;
    buf = tmp.data();
    PIN_SafeCopy(buf, reinterpret_cast<const VOID *>(low), size);

    PIN_GetLock(&context.write_lock, 1);
    {
        context.trace_file << "Loaded image: 0x" << low << ":0x" << high << " -> "
                << IMG_Name(img) << " Bytes: ";
        LOG("Loaded image: 0x" + hexstr(low) + ":0x" + hexstr(high) + " -> " +
            IMG_Name(img) + "\n");

        for (UINT32 i = 0; i < size; i++) {
            context.trace_file << std::hex << std::setw(2) << std::setfill('0') << (buf[i] & 0xff);
        }

        context.trace_file << std::endl;
    }
    PIN_ReleaseLock(&context.write_lock);

    for (const auto &[spec_img, offset]: context.pending_start_specs) {
        if (spec_img == img_name) {
            ADDRINT target = low + offset;
            context.start_addrs.push_back(target);
            LOG("Resolved start location for " + spec_img + " -> 0x" +
                hexstr(target) + "\n");
        }
    }

    for (const auto &[spec_img, offset]: context.pending_stop_specs) {
        if (spec_img == img_name) {
            ADDRINT target = low + offset;
            context.stop_addrs.push_back(target);
            LOG("Resolved stop location for " + spec_img + " -> 0x" + hexstr(target) +
                "\n");
        }
    }

    if (context.image_manager->isWhiteListed(img_name)) {
        context.image_manager->addImage(img_name, low, high);
    }
}

static VOID on_image_unload(const IMG img, VOID *v) {
    auto &context = *static_cast<ToolContext *>(v);
    if (IMG_IsVDSO(img)) {
        return;
    }

    context.image_manager->removeImage(IMG_LowAddress(img));

    const ADDRINT low = IMG_LowAddress(img);
    const ADDRINT high = IMG_HighAddress(img);

    context.trace_file << "Unloaded image: 0x" << low << ":0x" << high << " -> "
            << IMG_Name(img) << std::endl;
    LOG("Unloaded image: 0x" + hexstr(low) + ":0x" + hexstr(high) + " -> " +
        IMG_Name(img) + "\n");
}

static VOID PIN_FAST_ANALYSIS_CALL record_diff(const CONTEXT *cpu, const ADDRINT pc,
                                               VOID *v) {
    auto &context = *static_cast<ToolContext *>(v);
    const auto tid = PIN_ThreadId();
    ThreadData *data = context.GetThreadLocalData(tid);

    ADDRINT val;
    std::ostringstream oss;
    oss << std::hex;
    oss << "tid=" << tid << ",";

    for (int reg = REG_GR_BASE; reg <= static_cast<int>(REG_GR_LAST); ++reg) {
        PIN_GetContextRegval(cpu, static_cast<REG>(reg), reinterpret_cast<UINT8 *>(&val));

        if (val == data->m_cpu[reg]) continue;

        oss << REG_StringShort(static_cast<REG>(reg)) << "=0x" << val << ",";
        data->m_cpu[reg] = val;
    }

    oss << PC << "=0x" << pc;

    const ADDRINT largest =
            std::max(data->largestSize,
                     std::max(data->mem_r_size,
                              std::max(data->mem_r2_size, data->mem_w_size)));
    std::vector<unsigned char> tmp(largest);
    unsigned char *buf = nullptr;
    buf = tmp.data();

    for (auto const &[_, ev]: data->mem_events) {
        if (ev.size == 0) continue;

        PIN_SafeCopy(buf, reinterpret_cast<const VOID *>(ev.addr), ev.size);

        // It's easier to just call all these events as access instead of an
        // explicit read or write. Especially since the trace is not keeping track
        // of where these occurred
        constexpr auto atype = "ma";

        oss << "," << atype << "=0x" << ev.addr << ":";

        for (UINT32 i = 0; i < ev.size; i++) {
            oss << std::hex << std::setw(2) << std::setfill('0') << (buf[i] & 0xff);
        }
    }

    data->mem_events.clear();
    data->largestSize = 0;

    if (data->mem_r_size) {
        PIN_SafeCopy(buf, reinterpret_cast<const VOID *>(data->mem_r_addr), data->mem_r_size);
        oss << ",mr=0x" << data->mem_r_addr << ":";

        for (UINT32 i = 0; i < data->mem_r_size; i++) {
            oss << std::hex << std::setw(2) << std::setfill('0')
                    << (buf[i] & 0xff);
        }

        data->mem_r_size = 0;
    }

    if (data->mem_r2_size) {
        PIN_SafeCopy(buf, reinterpret_cast<const VOID *>(data->mem_r2_addr), data->mem_r2_size);
        oss << ",mr=0x" << data->mem_r2_addr << ":";

        for (UINT32 i = 0; i < data->mem_r2_size; i++) {
            oss << std::hex << std::setw(2) << std::setfill('0')
                    << (buf[i] & 0xff);
        }

        data->mem_r2_size = 0;
    }

    if (data->mem_w_size) {
        PIN_SafeCopy(buf, reinterpret_cast<const VOID *>(data->mem_w_addr), data->mem_w_size);
        oss << ",mw=0x" << data->mem_w_addr << ":";

        for (UINT32 i = 0; i < data->mem_w_size; i++) {
            oss << std::hex << std::setw(2) << std::setfill('0')
                    << (buf[i] & 0xff);
        }

        data->mem_w_size = 0;
    }

    oss << std::endl;

    PIN_GetLock(&context.write_lock, 1);
    {
        context.trace_file << oss.str();
    }
    PIN_ReleaseLock(&context.write_lock);
}

static VOID PIN_FAST_ANALYSIS_CALL record_read(const THREADID tid, const ADDRINT access_addr,
                                               const UINT32 access_size, VOID *v,
                                               const BOOL recordMemOnlyOp) {
    auto const &context = *static_cast<ToolContext *>(v);
    ThreadData *data = context.GetThreadLocalData(tid);
    if (!recordMemOnlyOp) {
        data->mem_r_addr = access_addr;
        data->mem_r_size = access_size;
    } else {
        add_mem_event(data, access_addr, access_size, 1);
    }
}

static VOID PIN_FAST_ANALYSIS_CALL record_read2(const THREADID tid, const ADDRINT access_addr,
                                                const UINT32 access_size, VOID *v,
                                                const BOOL recordMemOnlyOp) {
    auto const &context = *static_cast<ToolContext *>(v);
    ThreadData *data = context.GetThreadLocalData(tid);
    if (!recordMemOnlyOp) {
        data->mem_r2_addr = access_addr;
        data->mem_r2_size = access_size;
    } else {
        add_mem_event(data, access_addr, access_size, 1);
    }
}

static VOID PIN_FAST_ANALYSIS_CALL record_write(const THREADID tid, const ADDRINT access_addr,
                                                const UINT32 access_size, VOID *v,
                                                const BOOL recordMemOnlyOp) {
    auto const &context = *static_cast<ToolContext *>(v);
    ThreadData *data = context.GetThreadLocalData(tid);
    if (!recordMemOnlyOp) {
        data->mem_w_addr = access_addr;
        data->mem_w_size = access_size;
    } else {
        add_mem_event(data, access_addr, access_size, 2);
    }
}

static VOID PIN_FAST_ANALYSIS_CALL record_after_instruction(const CONTEXT *cpu,
                                                            const ADDRINT target, VOID *v) {
    auto &context = *static_cast<ToolContext *>(v);
    if (should_trace(&context, target)) {
        record_diff(cpu, target, v);
    }
}

static VOID instrument_inst(const INS ins, VOID *v, const BOOL recordNext, const BOOL recordMemOnly) {
    auto &context = *static_cast<ToolContext *>(v);
    const BOOL shouldTrace = should_trace(&context, INS_Address(ins));
    if (KnobCollectMem.Value() == 0 && !shouldTrace) {
        return;
    }

    if (!recordMemOnly && shouldTrace) {
        INS_InsertCall(ins, IPOINT_BEFORE, reinterpret_cast<AFUNPTR>(record_diff),
                       IARG_FAST_ANALYSIS_CALL, IARG_CONST_CONTEXT, IARG_INST_PTR,
                       IARG_PTR, v, IARG_END);
    }

    if (!recordMemOnly && recordNext && INS_IsControlFlow(ins)) {
        INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, reinterpret_cast<AFUNPTR>(record_after_instruction),
                       IARG_FAST_ANALYSIS_CALL, IARG_CONTEXT,
                       IARG_BRANCH_TARGET_ADDR, IARG_PTR, v, IARG_END);
    }

    const BOOL memoryRecord = recordMemOnly || !shouldTrace;

    if (INS_IsMemoryRead(ins) || INS_IsMemoryWrite(ins)) {
        if (INS_IsMemoryRead(ins)) {
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, reinterpret_cast<AFUNPTR>(record_read),
                                     IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                                     IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
                                     IARG_PTR, v, IARG_BOOL, memoryRecord, IARG_END);
        }

        if (INS_HasMemoryRead2(ins)) {
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, reinterpret_cast<AFUNPTR>(record_read2),
                                     IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                                     IARG_MEMORYREAD2_EA, IARG_MEMORYREAD_SIZE,
                                     IARG_PTR, v, IARG_BOOL, memoryRecord, IARG_END);
        }

        if (INS_IsMemoryWrite(ins)) {
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, reinterpret_cast<AFUNPTR>(record_write),
                                     IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                                     IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE,
                                     IARG_PTR, v, IARG_BOOL, memoryRecord, IARG_END);
        }
    }
}

static VOID instrument_inst_cb(const INS ins, VOID *v) { instrument_inst(ins, v, false, false); }

static VOID instrument_trace_cb(const TRACE trace, VOID *v) {
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            if (ins == BBL_InsHead(bbl) || (ins == BBL_InsTail(bbl) &&
                                            BBL_InsHead(bbl) != BBL_InsTail(bbl))) {
                instrument_inst(ins, v, false, false);
            } else if (KnobCollectMem.Value() == 1) {
                instrument_inst(ins, v, false, true);
            }
        }
    }
}

static VOID instrument_routine_cb(const TRACE trace, VOID *v) {
    static bool recordNext = false;
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            if (INS_IsCall(ins) || INS_IsRet(ins) || (INS_IsControlFlow(ins) && !INS_IsCall(ins) &&
                                                      INS_Category(ins) != XED_CATEGORY_COND_BR && !INS_IsRet(ins) &&
                                                      !BBL_Valid(BBL_Next(bbl)))) {
                instrument_inst(ins, v, true, false);
            } else if (INS_IsSyscall(ins)) {
                recordNext = true;
                instrument_inst(ins, v, false, false);
            } else if (recordNext) {
                recordNext = false;
                instrument_inst(ins, v, true, false);
            } else if (KnobCollectMem.Value() == 1) {
                instrument_inst(ins, v, false, true);
            }
        }
    }
}

static INT32 usage() {
    std::cerr << "TenetPlusPlus pintool tracer" << std::endl;
    std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;
    return -1;
}

static EXCEPT_HANDLING_RESULT exception_handler_cb(THREADID tid, EXCEPTION_INFO *pExceptInfo,
                                                   PHYSICAL_CONTEXT *pPhysCtxt, VOID *v) {
    std::cout << pExceptInfo->ToString() << std::endl;
    return EHR_UNHANDLED;
}

int main(int argc, char *argv[]) {
    PIN_InitSymbols();

    if (PIN_Init(argc, argv)) {
        return usage();
    }

    PIN_AddInternalExceptionHandler(exception_handler_cb, nullptr);

    auto logFile = KnobOutputFilePrefix.Value() + ".trace";
    LOG("Trace will be saved in " + logFile + "\n");

    auto context = std::make_unique<ToolContext>(logFile);
    context->image_manager = std::make_unique<ImageManager>();

    for (unsigned i = 0; i < KnobModuleWhitelist.NumberOfValues(); ++i) {
        LOG("White-listing image: " + KnobModuleWhitelist.Value(i) + "\n");
        context->tracing_enabled = false;
        context->image_manager->addWhiteListedImage(KnobModuleWhitelist.Value(i));
    }

    if (KnobStartAt.NumberOfValues() > 0) {
        context->wait_for_start = true;
        context->tracing_enabled = false;

        std::regex pattern(R"(^(.+):([0-9a-fA-F]+)$)");
        std::smatch matches;

        for (unsigned i = 0; i < KnobStartAt.NumberOfValues(); ++i) {
            if (!std::regex_match(KnobStartAt.Value(i), matches, pattern)) {
                continue;
            }
            ADDRINT offset = std::stoi(matches[2], nullptr, 16);
            if (KnobModuleWhitelist.NumberOfValues() > 0) {
                context->image_manager->addWhiteListedImage(KnobStartAt.Value(i));
            }
            context->pending_start_specs.emplace_back(matches[1], offset);
        }

        context->start_and_end_defined = true;
    }

    if (KnobStopAt.NumberOfValues() > 0) {
        std::regex pattern(R"(^(.+):([0-9a-fA-F]+)$)");
        std::smatch matches;

        for (unsigned i = 0; i < KnobStopAt.NumberOfValues(); ++i) {
            if (!std::regex_match(KnobStopAt.Value(i), matches, pattern)) {
                continue;
            }
            ADDRINT offset = std::stoi(matches[2], nullptr, 16);
            if (KnobModuleWhitelist.NumberOfValues() > 0) {
                context->image_manager->addWhiteListedImage(KnobStopAt.Value(i));
            }
            context->pending_stop_specs.emplace_back(matches[1], offset);
        }
        context->start_and_end_defined = true;
    }

    PIN_AddThreadStartFunction(on_thread_start, std::move(context).get());

    IMG_AddInstrumentFunction(on_image_load, std::move(context).get());
    IMG_AddUnloadFunction(on_image_unload, std::move(context).get());

    switch (auto inst = static_cast<TraceGranularity>(KnobTraceGranularity.Value())) {
        case TraceGranularity::TRACE_INSTRUCTION:
            LOG("Running with instruction level tracing\n");
            INS_AddInstrumentFunction(instrument_inst_cb, std::move(context).get());
            break;
        case TraceGranularity::TRACE_BASIC_BLOCK:
            LOG("Running with block level tracing\n");
            TRACE_AddInstrumentFunction(instrument_trace_cb, std::move(context).get());
            break;
        case TraceGranularity::TRACE_ROUTINE:
            LOG("Running with routine level tracing\n");
            TRACE_AddInstrumentFunction(instrument_routine_cb, std::move(context).get());
            break;
        default:
            std::cerr << "Unknown trace type: " << static_cast<int>(inst) << "\n";
            abort();
    }

    PIN_StartProgram();

    return 0;
}
