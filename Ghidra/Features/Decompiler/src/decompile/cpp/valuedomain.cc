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
#include "valuedomain.hh"
#include "funcdata.hh"
#include "architecture.hh"
#include "typeop.hh"
#include <limits>

namespace ghidra {
namespace {
struct DomainValue {
  uintb value;
  bool rooted;
  DomainValue(uintb v=0,bool r=false) : value(v),rooted(r) {}
};

// A source is one exact SSA LOAD result. In particular, a second LOAD from an
// equal-looking pointer is not evidence that the values or lifetimes agree.
class DomainEvaluator {
  Architecture *arch;
  Varnode *source;
  uintb seed;
  int4 fuel;
  map<Varnode *,DomainValue> memo;
  set<Varnode *> pending;
public:
  DomainEvaluator(Architecture *a,Varnode *s,uintb v) : arch(a),source(s),seed(v),fuel(256) {}
  bool evaluate(Varnode *vn,DomainValue &result,int4 depth=0) {
    if (vn == (Varnode *)0 || vn->getSize() > sizeof(uintb) || vn->getSize() <= 0) return false;
    if (vn == source) { result = DomainValue(seed,true); return true; }
    if (vn->isConstant()) { result = DomainValue(vn->getOffset(),false); return true; }
    map<Varnode *,DomainValue>::const_iterator found = memo.find(vn);
    if (found != memo.end()) { result = (*found).second; return true; }
    if (!vn->isWritten() || depth >= 32 || --fuel < 0 || !pending.insert(vn).second) return false;
    PcodeOp *op = vn->getDef();
    bool unary = false;
    switch(op->code()) {
      case CPUI_COPY: case CPUI_INT_ZEXT: case CPUI_INT_SEXT:
      case CPUI_INT_NEGATE: case CPUI_INT_2COMP: case CPUI_BOOL_NEGATE:
        unary = true; break;
      case CPUI_INT_AND: case CPUI_INT_OR: case CPUI_INT_XOR:
      case CPUI_INT_LEFT: case CPUI_INT_RIGHT: case CPUI_INT_SRIGHT:
      case CPUI_INT_ADD: case CPUI_INT_SUB: case CPUI_SUBPIECE:
      case CPUI_INT_EQUAL: case CPUI_INT_NOTEQUAL:
      case CPUI_INT_LESS: case CPUI_INT_LESSEQUAL:
      case CPUI_INT_SLESS: case CPUI_INT_SLESSEQUAL:
      case CPUI_BOOL_AND: case CPUI_BOOL_OR: case CPUI_BOOL_XOR:
        break;
      default: return false;
    }
    if (op->numInput() != (unary ? 1 : 2)) return false;
    DomainValue left,right;
    if (!evaluate(op->getIn(0),left,depth+1)) return false;
    if (!unary && !evaluate(op->getIn(1),right,depth+1)) return false;
    TypeOp *behavior = arch->inst[op->code()];
    uintb output = unary
        ? behavior->evaluateUnary(vn->getSize(),op->getIn(0)->getSize(),left.value)
        : behavior->evaluateBinary(vn->getSize(),op->getIn(0)->getSize(),left.value,right.value);
    result = DomainValue(output & calc_mask(vn->getSize()),left.rooted || right.rooted);
    pending.erase(vn);
    memo[vn] = result;
    return true;
  }
};

static bool matchesUse(const ValueDomainConstraint &domain,Funcdata *fd,PcodeOp *use)
{
  return domain.getOwnerEntry() == fd->getAddress() &&
      (!domain.isUseRestricted() || domain.getSwitchAddress() == use->getAddr());
}

static PcodeOp *uniqueOperation(Funcdata *fd,const Address &address,OpCode opcode)
{
  PcodeOp *result = (PcodeOp *)0;
  for(list<PcodeOp *>::const_iterator it=fd->beginOpAlive();it!=fd->endOpAlive();++it) {
    PcodeOp *op = *it;
    if (op->getAddr() != address || op->code() != opcode) continue;
    if (result != (PcodeOp *)0) return (PcodeOp *)0;
    result = op;
  }
  return result;
}

// Removing the required edge must disconnect entry from the use. Dominance of
// the guard block alone would also admit the opposite arm or an arm with a bypass.
static bool requiredEdge(Funcdata *fd,PcodeOp *branch,PcodeOp *use,bool truth)
{
  BlockBasic *guard = branch->getParent();
  BlockBasic *target = use->getParent();
  const BlockGraph &graph = fd->getBasicBlocks();
  if (guard == (BlockBasic *)0 || target == (BlockBasic *)0 || graph.getSize() == 0 ||
      guard->sizeOut() != 2) return false;
  // The contract names the original taken/fall-through edge. The current
  // condition may have been negated and boolean_flip normalized away.
  int4 slot = (truth != branch->isFallthruTrue()) ? 1 : 0;
  FlowBlock *successor = guard->getOut(slot);
  if (successor == guard) return false;
  FlowBlock *entry = graph.getBlock(0);
  vector<FlowBlock *> work(1,target);
  set<FlowBlock *> seen;
  bool encountered = false;
  while(!work.empty()) {
    FlowBlock *block = work.back(); work.pop_back();
    if (!seen.insert(block).second) continue;
    if (block == entry) return false;
    for(int4 i=0;i<block->sizeIn();++i) {
      FlowBlock *predecessor = block->getIn(i);
      if (predecessor == guard && block == successor && block->getInRevIndex(i) == slot) {
        encountered = true;
        continue;
      }
      work.push_back(predecessor);
    }
  }
  return encountered;
}

static bool makeRange(const set<uintb> &values,int4 size,CircleRange &range)
{
  if (values.empty()) return false;
  if (values.size() == 1) { range.setRange(*values.begin(),size); return true; }
  set<uintb>::const_iterator it = values.begin();
  uintb first = *it++;
  uintb step = *it - first;
  if (step == 0 || (step & (step-1)) != 0 || step > std::numeric_limits<int4>::max()) return false;
  uintb previous = *it++;
  for(;it!=values.end();++it) {
    if (*it - previous != step) return false;
    previous = *it;
  }
  CircleRange result(first,(previous+step)&calc_mask(size),size,(int4)step);
  if (result.getSize() != values.size()) return false;
  range = result;
  return true;
}
}

bool ValueDomainAnalysis::getRange(Funcdata *fd,Varnode *value,PcodeOp *use,CircleRange &range)
{
  bool found = false;
  const vector<ValueDomainConstraint> &domains = fd->getOverride().getValueDomainConstraints();
  for(vector<ValueDomainConstraint>::const_iterator it=domains.begin();it!=domains.end();++it) {
    const ValueDomainConstraint &domain = *it;
    if (!matchesUse(domain,fd,use) || domain.getLast()-domain.getFirst() >= 65536) continue;
    PcodeOp *load = uniqueOperation(fd,domain.getLoadAddress(),CPUI_LOAD);
    if (load == (PcodeOp *)0 || load->getOut() == (Varnode *)0 ||
        load->getOut()->getSize() != domain.getOutputSize()) continue;
    PcodeOp *guard = (PcodeOp *)0;
    if (!domain.getGuardAddress().isInvalid()) {
      guard = uniqueOperation(fd,domain.getGuardAddress(),CPUI_CBRANCH);
      if (guard == (PcodeOp *)0 || guard->numInput() != 2 ||
          !requiredEdge(fd,guard,use,domain.isGuardTrue())) continue;
    }
    set<uintb> values;
    bool valid = true;
    try {
      for(uintb seed=domain.getFirst();;) {
        DomainEvaluator evaluator(fd->getArch(),load->getOut(),seed);
        DomainValue result;
        if (!evaluator.evaluate(value,result) || !result.rooted) { valid=false; break; }
        if (guard != (PcodeOp *)0) {
          DomainValue condition;
          if (!evaluator.evaluate(guard->getIn(1),condition) || !condition.rooted) { valid=false; break; }
          bool currentTrueEdge = (condition.value != 0) != guard->isBooleanFlip();
          bool requiredTrueEdge = domain.isGuardTrue() != guard->isFallthruTrue();
          if (currentTrueEdge == requiredTrueEdge) values.insert(result.value);
        }
        else values.insert(result.value);
        if (seed == domain.getLast()) break; // Inclusive unsigned bounds, including UINT64_MAX
        ++seed;
      }
    }
    catch (LowlevelError &error) { valid = false; }
    CircleRange candidate;
    if (!valid || !makeRange(values,value->getSize(),candidate)) continue;
    if (found && !(candidate == range)) return false;
    range = candidate;
    found = true;
  }
  return found;
}

bool ValueDomainAnalysis::preservesGuard(Funcdata *fd,PcodeOp *branch,PcodeOp *use)
{
  const vector<ValueDomainConstraint> &domains = fd->getOverride().getValueDomainConstraints();
  for(vector<ValueDomainConstraint>::const_iterator it=domains.begin();it!=domains.end();++it) {
    if (matchesUse(*it,fd,use) && !it->getGuardAddress().isInvalid() &&
        it->getGuardAddress() == branch->getAddr()) {
      // Normalization has already replaced BRANCHIND's target expression with
      // the switch selector. A rejected contract must not alter guard folding.
      PcodeOp *load = uniqueOperation(fd,it->getLoadAddress(),CPUI_LOAD);
      PcodeOp *guard = uniqueOperation(fd,it->getGuardAddress(),CPUI_CBRANCH);
      if (load == (PcodeOp *)0 || load->getOut() == (Varnode *)0 ||
          load->getOut()->getSize() != it->getOutputSize() || guard != branch) continue;
      // The aggregate range query below may also see other LOAD contracts.
      // Establish this record's selector dependency before consulting it.
      DomainEvaluator evaluator(fd->getArch(),load->getOut(),it->getFirst());
      DomainValue selector;
      try {
        if (!evaluator.evaluate(use->getIn(0),selector) || !selector.rooted) continue;
      }
      catch (LowlevelError &error) { continue; }
      CircleRange proven;
      if (getRange(fd,use->getIn(0),use,proven)) return true;
    }
  }
  return false;
}
} // End namespace ghidra
