#include "block_conflict.hh"
#include "funcdata.hh"

namespace ghidra {

void BlockConflictGraph::build(const Funcdata &data)
{
  clear();
  int4 nblocks = data.getBasicBlocks().getSize();
  adj.resize(nblocks);

  // Use a per-block set of "neighbour ids encountered so far" to dedupe edges.
  std::vector<std::unordered_set<int4>> seen(nblocks);

  PcodeOpTree::const_iterator it;
  for (it = data.beginOpAll(); it != data.endOpAll(); ++it) {
    PcodeOp *op = (*it).second;
    if (op->isDead()) continue;
    Varnode *out = op->getOut();
    if (out == (Varnode *)0) continue;
    BlockBasic *defBlock = op->getParent();
    if (defBlock == (BlockBasic *)0) continue;
    int4 defIdx = defBlock->getIndex();

    list<PcodeOp *>::const_iterator dit;
    for (dit = out->beginDescend(); dit != out->endDescend(); ++dit) {
      PcodeOp *useOp = *dit;
      if (useOp->isDead()) continue;
      BlockBasic *useBlock = useOp->getParent();
      if (useBlock == (BlockBasic *)0) continue;
      int4 useIdx = useBlock->getIndex();
      if (useIdx == defIdx) continue;

      // Add symmetric edge (defIdx, useIdx) if not yet present.
      if (seen[defIdx].insert(useIdx).second)
        adj[defIdx].push_back(useIdx);
      if (seen[useIdx].insert(defIdx).second)
        adj[useIdx].push_back(defIdx);
    }
  }

  // Sort adjacency for deterministic iteration.
  for (auto &v : adj)
    std::sort(v.begin(), v.end());

  ready = true;
}

void BlockConflictGraph::colorBlocks(void)
{
  int4 n = (int4)adj.size();
  color.assign(n, -1);
  maxColor = -1;

  // Greedy: visit blocks in index order; assign smallest color unused by any neighbour.
  std::vector<bool> used;
  for (int4 i = 0; i < n; ++i) {
    used.assign(maxColor + 2, false);
    for (int4 nbr : adj[i]) {
      if (nbr < i && color[nbr] >= 0 && color[nbr] < (int4)used.size())
        used[color[nbr]] = true;
    }
    int4 c = 0;
    while (c < (int4)used.size() && used[c]) ++c;
    color[i] = c;
    if (c > maxColor) maxColor = c;
  }
}

std::vector<int4> BlockConflictGraph::getColorGroup(int4 c) const
{
  std::vector<int4> result;
  for (int4 i = 0; i < (int4)color.size(); ++i)
    if (color[i] == c) result.push_back(i);
  return result;
}

int4 BlockConflictGraph::edgeCount(void) const
{
  int4 total = 0;
  for (const auto &v : adj) total += (int4)v.size();
  return total / 2;
}

} // namespace ghidra
