/* ### See parallel.hh */
#include "parallel.hh"
#include "parallel_safety.hh"
#include <cstdlib>
#include <cstring>

namespace ghidra {

// P4-d5: process-global flag.  See parallel_safety.hh.
std::atomic<bool> g_parallelActive{false};

static bool parseBoolEnv(const char *name)
{
  const char *v = std::getenv(name);
  if (v == nullptr) return false;
  if (v[0] == '\0') return false;
  if (v[0] == '0' && v[1] == '\0') return false;
  return true;
}

static int parseIntEnv(const char *name, int def)
{
  const char *v = std::getenv(name);
  if (v == nullptr || v[0] == '\0') return def;
  return std::atoi(v);
}

void initParallelActiveFromEnv(void)
{
  // Engage locks iff a parallel mode is requested.  Match the conditions
  // checked in action.cc (getIntraFunctionWorkers > 1) and heritage.cc
  // (DECOMP_PARALLEL_GUARDCALLS=1).
  int workers = parseIntEnv("DECOMP_INTRA_WORKERS", 0);
  bool guardCalls = parseBoolEnv("DECOMP_PARALLEL_GUARDCALLS");
  bool active = (workers > 1) || guardCalls;
  g_parallelActive.store(active, std::memory_order_relaxed);
}

ThreadPool::ThreadPool(int n)
{
  workers.reserve(n);
  for (int i = 0; i < n; i++)
    workers.emplace_back([this]() { this->workerLoop(); });
}

ThreadPool::~ThreadPool(void)
{
  {
    std::unique_lock<std::mutex> lock(queueMutex);
    stop = true;
  }
  cvAvail.notify_all();
  for (std::thread &t : workers)
    if (t.joinable()) t.join();
}

void ThreadPool::workerLoop(void)
{
  for (;;) {
    std::function<void()> task;
    {
      std::unique_lock<std::mutex> lock(queueMutex);
      cvAvail.wait(lock, [this]() { return stop || !tasks.empty(); });
      if (stop && tasks.empty()) return;
      task = std::move(tasks.front());
      tasks.pop();
    }
    task();
    if (activeTasks.fetch_sub(1) == 1) {
      // Last task finished; wake any waiter.
      std::unique_lock<std::mutex> lock(queueMutex);
      cvDone.notify_all();
    }
  }
}

void ThreadPool::submit(std::function<void()> task)
{
  activeTasks.fetch_add(1);
  {
    std::unique_lock<std::mutex> lock(queueMutex);
    tasks.push(std::move(task));
  }
  cvAvail.notify_one();
}

void ThreadPool::waitAll(void)
{
  std::unique_lock<std::mutex> lock(queueMutex);
  cvDone.wait(lock, [this]() { return activeTasks.load() == 0; });
}

ThreadPool &ThreadPool::getInstance(int numWorkers)
{
  // Construct on first call; reused thereafter.  Note: thread-safe per C++11
  // (static-local init is guaranteed thread-safe), so multiple Funcdata
  // decompiles in flight may all call getInstance() concurrently without race.
  static ThreadPool pool(numWorkers > 0 ? numWorkers : 1);
  return pool;
}

} // namespace ghidra
