/* ###
 * Lightweight persistent thread pool for intra-function parallel work.
 * Initialized lazily with a configurable worker count.
 *
 * Usage:
 *   ThreadPool &pool = ThreadPool::getInstance(numWorkers);
 *   for (int i = 0; i < N; i++) pool.submit([&, i]() { ... });
 *   pool.waitAll();
 *
 * Workers persist for process lifetime to amortize creation cost across many
 * ActionPool::apply() invocations.  Re-sizing is not supported once created
 * (the instance is parametrized by the worker count of the first caller).
 */
#ifndef __GHIDRA_PARALLEL_HH__
#define __GHIDRA_PARALLEL_HH__

#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

namespace ghidra {

class ThreadPool {
  std::vector<std::thread> workers;
  std::queue<std::function<void()>> tasks;
  std::mutex queueMutex;
  std::condition_variable cvAvail;
  std::condition_variable cvDone;
  std::atomic<int> activeTasks{0};
  bool stop = false;

  void workerLoop(void);
public:
  ThreadPool(int n);
  ~ThreadPool(void);
  void submit(std::function<void()> task);
  void waitAll(void);
  int size(void) const { return (int)workers.size(); }

  /// Lazily-initialized global pool.  First caller's numWorkers wins; subsequent
  /// calls return the same instance regardless of numWorkers argument.
  static ThreadPool &getInstance(int numWorkers);
};

} // namespace ghidra
#endif
