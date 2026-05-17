/* ###
 * Path 2: Block-DAG static partitioning for intra-function parallel decompilation.
 *
 * Builds a "conflict graph" between BasicBlocks of a function.  Two blocks conflict
 * if some op in block A produces a Varnode used in block B (or vice-versa).  Blocks
 * that do NOT conflict (no shared def-use chain) can be processed concurrently by
 * ActionPool::applyBlockParallel without race.
 *
 * The graph is built once per heritage stabilization point and rebuilt only when
 * basic-block structure changes (rare during ActionPool sweeps).  Greedy coloring
 * gives independent block groups: blocks with the same color have no pairwise
 * conflict, so all blocks of one color can run in parallel.
 */
#ifndef __GHIDRA_BLOCK_CONFLICT_HH__
#define __GHIDRA_BLOCK_CONFLICT_HH__

#include "types.h"
#include <unordered_set>
#include <vector>

namespace ghidra {

class Funcdata;
class BlockBasic;

class BlockConflictGraph {
  /// Node[i] = sorted list of block indices that conflict with block i.
  std::vector<std::vector<int4>> adj;
  /// Coloring result: color[i] = color assigned to block i.  -1 if unbuilt.
  std::vector<int4> color;
  /// Maximum color used (= color count - 1).
  int4 maxColor;
  /// Whether the graph reflects the current state of \b data.
  bool ready;

public:
  BlockConflictGraph(void) : maxColor(-1), ready(false) {}
  void clear(void) { adj.clear(); color.clear(); maxColor = -1; ready = false; }
  bool isReady(void) const { return ready; }

  /// \brief Build the conflict graph for the given function.
  /// Edge (a,b) is added whenever any Varnode defined in block a is used in block b (or vice-versa).
  /// Idempotent: re-call rebuilds in-place.
  void build(const Funcdata &data);

  /// \brief Greedy color: assign each block a non-negative color id such that no edge
  /// connects two blocks with the same color.  Smallest color first per block.
  void colorBlocks(void);

  /// \brief Return number of distinct colors (= max parallelism degree achievable).
  int4 getColorCount(void) const { return maxColor + 1; }

  /// \brief Get blocks colored with the given color.
  std::vector<int4> getColorGroup(int4 c) const;

  /// \brief Get the color assigned to the given block index, or -1 if unbuilt/out-of-range.
  int4 colorOf(int4 blockIndex) const {
    if (blockIndex < 0 || blockIndex >= (int4)color.size()) return -1;
    return color[blockIndex];
  }

  /// \brief Number of blocks in the graph.
  int4 size(void) const { return (int4)adj.size(); }

  /// \brief Total number of edges (sum of adjacency list sizes divided by 2).
  int4 edgeCount(void) const;
};

} // namespace ghidra
#endif
