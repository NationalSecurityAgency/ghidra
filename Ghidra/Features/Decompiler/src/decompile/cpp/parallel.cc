/* ### See parallel.hh */
#include "parallel.hh"

namespace ghidra {

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
