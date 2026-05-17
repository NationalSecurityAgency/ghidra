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
#include "action.hh"
#include "funcdata.hh"
#include "parallel.hh"
#include "block_conflict.hh"

#include "coreaction.hh"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <unordered_map>
#include <map>
#include <set>
#include <atomic>
#include <cstdio>
#include <mutex>

namespace ghidra {

/// \brief Read intra-function parallel-decompile worker count from environment.
/// Cached on first call.  Returns 1 (= disabled) if env unset or invalid.
static int4 getIntraParallelWorkers(void)
{
  static int cached = -1;
  if (cached >= 0) return cached;
  const char *env = std::getenv("DECOMP_INTRA_WORKERS");
  cached = (env != nullptr) ? std::max(1, std::atoi(env)) : 1;
  return cached;
}

/// \brief Minimum number of ops required to engage parallel path (avoids overhead on small fns).
static int4 getIntraParallelMinOps(void)
{
  static int cached = -1;
  if (cached >= 0) return cached;
  const char *env = std::getenv("DECOMP_INTRA_MINOPS");
  cached = (env != nullptr) ? std::max(1, std::atoi(env)) : 1000;
  return cached;
}

/// \brief Path 2 instrumentation: print block conflict graph stats.
/// Set DECOMP_INTRA_GRAPH_STATS=1 to enable.
static bool getGraphStatsEnabled(void)
{
  static int cached = -1;
  if (cached >= 0) return cached != 0;
  const char *env = std::getenv("DECOMP_INTRA_GRAPH_STATS");
  cached = (env != nullptr && std::atoi(env) != 0) ? 1 : 0;
  return cached != 0;
}

/// \brief Path 3 never-fires blocklist: comma-separated rule names disabled at
/// ActionPool construction time.  Set via DECOMP_INTRA_RULE_BLOCKLIST=name1,name2,...
/// Use the rule-stats reporter (DECOMP_INTRA_RULE_STATS=1) to identify candidates:
/// rules with non-trivial test counts and zero fires for a given architecture/workload.
/// The list is loaded once and held in a static set; lookup is O(log N).
static const std::set<std::string>& getRuleBlocklist(void)
{
  static std::set<std::string> cache;
  static bool loaded = false;
  if (loaded) return cache;
  loaded = true;
  const char *env = std::getenv("DECOMP_INTRA_RULE_BLOCKLIST");
  if (env == nullptr || *env == '\0') return cache;
  std::string s(env);
  std::string cur;
  for (size_t i = 0; i <= s.size(); ++i) {
    if (i == s.size() || s[i] == ',') {
      if (!cur.empty()) cache.insert(cur);
      cur.clear();
    } else if (s[i] != ' ') {
      cur.push_back(s[i]);
    }
  }
  return cache;
}

/// \brief Path 3 dispatcher gate: route ActionPool::apply through applyBlockParallel.
/// Set DECOMP_INTRA_BLOCK_PARALLEL=1 to enable.  Requires DECOMP_INTRA_WORKERS>1.
static bool getBlockParallelEnabled(void)
{
  static int cached = -1;
  if (cached >= 0) return cached != 0;
  const char *env = std::getenv("DECOMP_INTRA_BLOCK_PARALLEL");
  cached = (env != nullptr && std::atoi(env) != 0) ? 1 : 0;
  return cached != 0;
}

/// \brief Path 4 dispatcher gate: enable parallel phase-2a scope_op_only rule
/// dispatch in applyBlockParallel.  Set DECOMP_INTRA_TRUE_PARALLEL=1 to enable.
/// Requires DECOMP_INTRA_BLOCK_PARALLEL=1 and DECOMP_INTRA_WORKERS>1.
/// When enabled, scope_op_only rules (~80% of fires) are dispatched in parallel
/// across block-conflict-graph color groups; non-scope_op_only rules are then
/// dispatched serially.  Funcdata mutators are protected by poolMutex (L1) and
/// per-Varnode descendMutex (L2); mod-counters are atomic (L3).
static bool getTrueParallelEnabled(void)
{
  static int cached = -1;
  if (cached >= 0) return cached != 0;
  const char *env = std::getenv("DECOMP_INTRA_TRUE_PARALLEL");
  cached = (env != nullptr && std::atoi(env) != 0) ? 1 : 0;
  return cached != 0;
}

/// \brief Path 3 instrumentation: per-scope rule-fire counters.
/// Set DECOMP_INTRA_SCOPE_STATS=1 to enable.  Counts are dumped at process exit.
/// Uses Path 2 mutation_scope annotations to validate the static distribution
/// (66 op_only / 25 block_local / 36 block_global / etc.) against runtime fire rates.
static bool getScopeStatsEnabled(void)
{
  static int cached = -1;
  if (cached >= 0) return cached != 0;
  const char *env = std::getenv("DECOMP_INTRA_SCOPE_STATS");
  cached = (env != nullptr && std::atoi(env) != 0) ? 1 : 0;
  return cached != 0;
}

// Five buckets corresponding to Rule::mutation_scope values, in declaration order.
static std::atomic<uint64_t> scopeTests[5] = {};
static std::atomic<uint64_t> scopeFires[5] = {};

static int4 scopeBucket(uint4 scope)
{
  // mutation_scope is a bitfield value (powers of two from 0x01 to 0x10).
  // Map to 0..4 by trailing-zero count.  Default scope_block_global on unknown.
  switch (scope) {
    case (uint4)Rule::scope_op_only:        return 0;
    case (uint4)Rule::scope_op_inputs_defs: return 1;
    case (uint4)Rule::scope_op_output_uses: return 2;
    case (uint4)Rule::scope_block_local:    return 3;
    case (uint4)Rule::scope_block_global:   return 4;
    default:                                return 4;
  }
}

/// \brief Path 3 instrumentation: per-rule (test, fire) counters.
/// Set DECOMP_INTRA_RULE_STATS=1 to enable.  Dumped at process exit,
/// sorted by test count descending.  Also reports never-fires (rules
/// with tests > 0 and fires == 0), which are candidates for static
/// elimination per architecture.
static bool getRuleStatsEnabled(void)
{
  static int cached = -1;
  if (cached >= 0) return cached != 0;
  const char *env = std::getenv("DECOMP_INTRA_RULE_STATS");
  cached = (env != nullptr && std::atoi(env) != 0) ? 1 : 0;
  return cached != 0;
}

// Rule stats are mutex-guarded and only updated when the env is set.
// Cost when disabled: a single atomic int load (the cached env check).
static std::mutex ruleStatsMutex;
static std::map<std::string, std::pair<uint64_t,uint64_t>> ruleStatsMap;

static void recordRuleResult(Rule *rl, int4 res)
{
  if (!getRuleStatsEnabled()) return;
  std::lock_guard<std::mutex> lock(ruleStatsMutex);
  auto &p = ruleStatsMap[rl->getName()];
  p.first += 1;
  if (res > 0) p.second += 1;
}

struct RuleStatsDumper {
  ~RuleStatsDumper(void) {
    if (!getRuleStatsEnabled()) return;
    std::lock_guard<std::mutex> lock(ruleStatsMutex);
    if (ruleStatsMap.empty()) return;
    std::vector<std::pair<std::string,std::pair<uint64_t,uint64_t>>>
      sorted(ruleStatsMap.begin(), ruleStatsMap.end());
    std::sort(sorted.begin(), sorted.end(),
              [](const std::pair<std::string,std::pair<uint64_t,uint64_t>> &a,
                 const std::pair<std::string,std::pair<uint64_t,uint64_t>> &b) {
                return a.second.first > b.second.first;
              });
    std::fprintf(stderr, "[rule-stats] rule_name                 tests     fires  fire_rate\n");
    int4 neverFires = 0;
    uint64_t neverFiresTests = 0;
    for (size_t i = 0; i < sorted.size(); ++i) {
      uint64_t t = sorted[i].second.first;
      uint64_t f = sorted[i].second.second;
      double pct = t ? (100.0 * (double)f / (double)t) : 0.0;
      if (t > 0 && f == 0) { ++neverFires; neverFiresTests += t; }
      std::fprintf(stderr, "[rule-stats] %-24s %10llu %10llu %6.3f%%\n",
                   sorted[i].first.c_str(),
                   (unsigned long long)t, (unsigned long long)f, pct);
    }
    std::fprintf(stderr, "[rule-stats] never-fires: %d / %zu rules, wasted_tests=%llu\n",
                 neverFires, sorted.size(), (unsigned long long)neverFiresTests);
    std::fflush(stderr);
  }
};
static RuleStatsDumper ruleStatsDumperInst;

// Dumper runs once at process teardown; only emits when stats enabled and any fires recorded.
struct ScopeStatsDumper {
  ~ScopeStatsDumper(void) {
    if (!getScopeStatsEnabled()) return;
    uint64_t totalTests = 0, totalFires = 0;
    for (int4 i = 0; i < 5; ++i) {
      totalTests += scopeTests[i].load(std::memory_order_relaxed);
      totalFires += scopeFires[i].load(std::memory_order_relaxed);
    }
    if (totalTests == 0) return;
    const char *names[5] = { "op_only", "inputs_defs", "output_uses", "block_local", "block_global" };
    std::fprintf(stderr, "[scope-stats] total tests=%llu fires=%llu\n",
                 (unsigned long long)totalTests, (unsigned long long)totalFires);
    for (int4 i = 0; i < 5; ++i) {
      uint64_t t = scopeTests[i].load(std::memory_order_relaxed);
      uint64_t f = scopeFires[i].load(std::memory_order_relaxed);
      double tpct = totalTests ? (100.0 * t / totalTests) : 0.0;
      double fpct = totalFires ? (100.0 * f / totalFires) : 0.0;
      std::fprintf(stderr, "[scope-stats] %-12s tests=%10llu (%5.2f%%) fires=%10llu (%5.2f%%)\n",
                   names[i],
                   (unsigned long long)t, tpct,
                   (unsigned long long)f, fpct);
    }
    std::fflush(stderr);
  }
};
static ScopeStatsDumper scopeStatsDumper;

/// Specify the name, group, and properties of the Action
/// \param f is the collection of property flags
/// \param nm is the Action name
/// \param g is the Action group
Action::Action(uint4 f,const string &nm,const string &g)

{
  flags = f;
  status = status_start;
  breakpoint = 0;
  name = nm;
  basegroup = g;
  count_tests = 0;
  count_apply = 0;
  lastSeenModCount = 0;	// 0 means "never seen"; Funcdata::globalModCount starts at 1, so first call always runs
}

/// If enabled, issue a warning that this Action has been applied
/// \param glb is the controlling Architecture
void Action::issueWarning(Architecture *glb)

{
  if ((flags&(rule_warnings_on|rule_warnings_given)) == rule_warnings_on) {
    flags |= rule_warnings_given;
    glb->printMessage("WARNING: Applied action "+name);
  }
}

/// Check if there was an active \e start break point on this action
/// \return true if there was a start breakpoint
bool Action::checkStartBreak(void)

{
  if ((breakpoint&(break_start|tmpbreak_start))!=0) {
    breakpoint &= ~(tmpbreak_start); // Clear breakpoint if temporary
    return true;		// Breakpoint was active
  }
  return false;			// Breakpoint was not active
}

#ifdef OPACTION_DEBUG

/// If this Action matches the given name, enable debugging.
/// \param nm is the Action name to match
/// \return true if debugging was enabled
bool Action::turnOnDebug(const string &nm)

{
  if (nm == name) {
    flags |= rule_debug;
    return true;
  }
  return false;
}

/// If this Action matches the given name, disable debugging.
/// \param nm is the Action name to match
/// \return true if debugging was disabled
bool Action::turnOffDebug(const string &nm)

{
  if (nm == name) {
    flags &= ~rule_debug;
    return true;
  }
  return false;
}
#endif

/// Print out the collected statistics for the Action to stream
/// \param s is the output stream
void Action::printStatistics(ostream &s) const

{
  s << name << dec << " Tested=" << count_tests << " Applied=" << count_apply << endl;
}

/// \param data is the new function \b this Action may affect
void Action::reset(Funcdata &data)

{
  status = status_start;
  flags &= ~rule_warnings_given; // Indicate a warning has not been given yet
  lastSeenModCount = 0;  // Force first-run after reset
}

/// Reset all the counts to zero
void Action::resetStats(void)

{
  count_tests = 0;
  count_apply = 0;
}

/// Check if there was an active \e action breakpoint on this Action
/// \return true if there was an action breakpoint
bool Action::checkActionBreak(void)

{
  if ((breakpoint&(break_action|tmpbreak_action))!=0) {
    breakpoint &= ~(tmpbreak_action); // Clear temporary breakpoint
    return true;		// Breakpoint was active
  }
  return false;			// Breakpoint was not active
}

/// The description is suitable for a console mode listing of actions
/// \param s is the output stream
/// \param num is a starting index to associate with the action (and its sub-actions)
/// \param depth is amount of indent necessary before printing
/// \return the next available index
int4 Action::print(ostream &s,int4 num,int4 depth) const

{
  s << setw(4) << dec << num;
  s << (char *) (((flags&rule_repeatapply)!=0) ? " repeat " : "        ");
  s << (char) (((flags&rule_onceperfunc)!=0) ? '!' : ' ');
  s << (char) (((breakpoint&(break_start|tmpbreak_start))!=0) ? 'S' : ' ');
  s << (char) (((breakpoint&(break_action|tmpbreak_action))!=0) ? 'A' : ' ');
  for(int4 i=0;i<depth*5+2;++i)
    s << ' ';
  s << name;
  return num+1;
}
  
/// This will the Action name and the next step to execute
/// \param s is the output stream
void Action::printState(ostream &s) const

{
  s << name;
  switch(status) {
  case status_repeat:
  case status_breakstarthit:
  case status_start:
    s << " start";
    break;
  case status_mid:
    s << ':';
    break;
  case status_end:
    s << " end";
  }
}

/// A breakpoint can be placed on \b this Action or some sub-action by properly
/// specifying the (sub)action name.
/// \param tp is the type of breakpoint (\e break_start, break_action, etc.)
/// \param specify is the (possibly sub)action to apply the break point to
/// \return true if a breakpoint was successfully set
bool Action::setBreakPoint(uint4 tp,const string &specify)

{
  Action *res = getSubAction(specify);
  if (res != (Action *)0) {
    res->breakpoint |= tp;
    return true;
  }
  Rule *rule = getSubRule(specify);
  if (rule != (Rule *)0) {
    rule->setBreak(tp);
    return true;
  }
  return false;
}

void Action::clearBreakPoints(void)

{
  breakpoint = 0;
}

/// If enabled, a warning will be printed whenever this action applies.
/// The warning can be toggled for \b this Action or some sub-action by
/// specifying its name.
/// \param val is the toggle value for the warning
/// \param specify is the name of the action or sub-action to toggle
/// \return true if the warning was successfully toggled
bool Action::setWarning(bool val,const string &specify)

{
  Action *res = getSubAction(specify);
  if (res != (Action *)0) {
    if (val)
      res->turnOnWarnings();
    else
      res->turnOffWarnings();
    return true;
  }
  Rule *rule = getSubRule(specify);
  if (rule != (Rule *)0) {
    if (val)
      rule->turnOnWarnings();
    else
      rule->turnOffWarnings();
    return true;
  }
  return false;
}

/// An individual Rule can be disabled by name, within \b this Action. It must
/// be specified by a ':' separated name \e path, from the root Action down
/// to the specific Rule.
/// \param specify is the name path
/// \return \b true if the Rule is successfully disabled
bool Action::disableRule(const string &specify)

{
  Rule *rule = getSubRule(specify);
  if (rule != (Rule *)0) {
    rule->setDisable();
    return true;
  }
  return false;
}

/// An individual Rule can be enabled by name, within \b this Action. It must
/// be specified by a ':' separated name \e path, from the root Action down
/// to the specific Rule.
/// \param specify is the name path
/// \return \b true if the Rule is successfully enabled
bool Action::enableRule(const string &specify)

{
  Rule *rule = getSubRule(specify);
  if (rule != (Rule *)0) {
    rule->clearDisable();
    return true;
  }
  return false;
}

/// Pull the next token from a ':' separated list of Action and Rule names
/// \param token will be filled with string up to the next ':'
/// \param remain will be whats left of the list of removing the token and ':'
/// \param is the list to pull the token from
static void next_specifyterm(string &token,string &remain,const string &specify)

{
  string::size_type res = specify.find(':');
  if (res != string::npos) {
    token = specify.substr(0,res);
    remain = specify.substr(res+1);
  }
  else {
    token = specify;
    remain.clear();
  }
}

/// If this Action matches the given name, it is returned. If the
/// name matches a sub-action, this is returned.
/// \param specify is the action name to match
/// \return the matching Action or sub-action
Action *Action::getSubAction(const string &specify)

{
  if (name == specify) return this;
  return (Action *)0;
}

/// Find a Rule, as a component of \b this Action, with the given name.
/// \param specify is the name of the rule
/// \return the matching sub-rule
Rule *Action::getSubRule(const string &specify)

{
  return (Rule *)0;
}

/// Run \b this Action until completion or a breakpoint occurs. Depending
/// on the behavior properties of this instance, the apply() method may get
/// called many times or none.  Generally the number of changes made by
/// the action is returned, but if a breakpoint occurs -1 is returned.
/// A successive call to perform() will "continue" from the break point.
/// \param data is the function being acted on
/// \return the number of changes or -1
int4 Action::perform(Funcdata &data)

{
  int4 res;

  // Opt-in dirty skip (via rule_modcount_skip): if no IR or state mutation has
  // occurred anywhere in the function since this Action last completed its
  // perform(), short-circuit the apply() body.  Uses the IR-only counter so
  // that non-IR state changes (nonzeromask, infertypes::writeBack) don't
  // invalidate the skip for actions whose work depends purely on IR (deadcode,
  // directwrite, varnodeprops, etc.).  Only triggers on status_start entry.
  if ((flags & rule_modcount_skip) != 0 &&
      status == status_start && lastSeenModCount != 0 &&
      lastSeenModCount == data.getIrModCount()) {
    count = 0;
    return 0;
  }

  do {
    switch(status) {
    case status_start:
      count = 0;		// No changes made yet by this action
      if (checkStartBreak()) {
	status = status_breakstarthit;
	return -1;		// Indicate partial completion
      }
      count_tests += 1;
    case status_breakstarthit:
    case status_repeat:
      lcount = count;
    case status_mid:
#ifdef OPACTION_DEBUG
      data.debugActivate();
#endif
      res = apply(data);	// Start or continue action
#ifdef OPACTION_DEBUG
      data.debugModPrint(getName());
#endif
      if (res < 0) {		// negative indicates partial completion
	status = status_mid;
	return res;
      }
      else if (lcount < count) { // Action has been applied
	issueWarning(data.getArch());
	count_apply += 1;
	if (checkActionBreak()) {
	  status = status_actionbreak;
	  return -1;		// Indicate action breakpoint
	}
#ifdef OPACTION_DEBUG
	else if (data.debugBreak()) {
	  status = status_actionbreak;
	  data.debugHandleBreak();
	  return -1;
	}
#endif
      }
      break;
    case status_end:
      return 0;			// Rule applied, do not repeat until reset
      break;
    case status_actionbreak:	// Returned -1 last time, but we do not reapply
      break;			// we either repeat, or return our count
    }
    status = status_repeat;
  } while((lcount<count)&&((flags&rule_repeatapply)!=0));

  if ((flags&(rule_onceperfunc|rule_oneactperfunc))!=0) {
    if ((count>0)||((flags&rule_onceperfunc)!=0))
      status = status_end;
    else
      status = status_start;
  }
  else
    status = status_start;

  // Record modCount on successful complete so opt-in actions can skip next round
  if ((flags & rule_modcount_skip) != 0)
    lastSeenModCount = data.getIrModCount();
  return count;
}

ActionGroup::~ActionGroup(void)

{
  vector<Action *>::iterator iter;
  
  for(iter=list.begin();iter!=list.end();++iter)
    delete *iter;
}

/// To be used only during the construction of \b this ActionGroup. This routine
/// adds an Action to the end of this group's list.
/// \param ac is the Action to add
void ActionGroup::addAction(Action *ac)

{
  list.push_back(ac);
}

void ActionGroup::clearBreakPoints(void)

{
  vector<Action *>::const_iterator iter;
  for(iter=list.begin();iter!= list.end();++iter)
    (*iter)->clearBreakPoints();
  Action::clearBreakPoints();
}

Action *ActionGroup::clone(const ActionGroupList &grouplist) const

{
  ActionGroup *res = (ActionGroup *)0;
  vector<Action *>::const_iterator iter;
  Action *ac;
  for(iter=list.begin();iter!=list.end();++iter) {
    ac = (*iter)->clone(grouplist);
    if (ac != (Action *)0) {
      if (res == (ActionGroup *)0)
	res = new ActionGroup(flags,getName());
      res->addAction(ac);
    }
  }
  return res;
}

void ActionGroup::reset(Funcdata &data)

{
  vector<Action *>::iterator iter;

  Action::reset(data);
  for(iter=list.begin();iter!=list.end();++iter)
    (*iter)->reset(data);	// Reset each subrule
}

void ActionGroup::resetStats(void)

{
  vector<Action *>::iterator iter;

  Action::resetStats();
  for(iter=list.begin();iter!=list.end();++iter)
    (*iter)->resetStats();
}

int4 ActionGroup::print(ostream &s,int4 num,int4 depth) const

{
  vector<Action *>::const_iterator titer;

  num = Action::print(s,num,depth);
  s << endl;
  for(titer=list.begin();titer!=list.end();++titer) {
    num = (*titer)->print(s,num,depth+1);
    if (state == titer)
      s << "  <-- ";
    s << endl;
  }
  return num;
}

void ActionGroup::printState(ostream &s) const

{
  Action *subact;

  Action::printState(s);
  if (status==status_mid) {
    subact = *state;
    subact->printState(s);
  }
}

Action *ActionGroup::getSubAction(const string &specify)

{
  string token,remain;
  next_specifyterm(token,remain,specify);
  if (name == token) {
    if (remain.empty()) return this;
  }
  else
    remain = specify;		// Still have to match entire specify
  
  vector<Action *>::iterator iter;
  Action *lastaction = (Action *)0;
  int4 matchcount = 0;
  for(iter=list.begin();iter!=list.end();++iter) {
    Action *testaction = (*iter)->getSubAction(remain);
    if (testaction != (Action *)0) {
      lastaction = testaction;
      matchcount += 1;
      if (matchcount > 1) return (Action *)0;
    }
  }
  return lastaction;
}

Rule *ActionGroup::getSubRule(const string &specify)

{
  string token,remain;
  next_specifyterm(token,remain,specify);
  if (name == token) {
    if (remain.empty()) return (Rule *)0;
  }
  else
    remain = specify;		// Still have to match entire specify

  vector<Action *>::iterator iter;
  Rule *lastrule = (Rule *)0;
  int4 matchcount = 0;
  for(iter=list.begin();iter!=list.end();++iter) {
    Rule *testrule = (*iter)->getSubRule(remain);
    if (testrule != (Rule *)0) {
      lastrule = testrule;
      matchcount += 1;
      if (matchcount > 1) return (Rule *)0;
    }
  }
  return lastrule;
}

int4 ActionGroup::apply(Funcdata &data)

{
  int4 res;

  if (status != status_mid)
    state = list.begin();	// Initialize the derived action
  for(;state!=list.end();++state) {
    res = (*state)->perform(data);
    if (res>0) {		// A change was made
      count  += res;
      if (checkActionBreak()) {	// Check if this is an action breakpoint
	++state;
	return -1;
      }
    }
    else if (res<0)		// Partial completion of member
      return -1;		// equates to partial completion of group action
  }

  return 0;			// Indicate successful completion
}

Action *ActionRestartGroup::clone(const ActionGroupList &grouplist) const

{
  ActionGroup *res = (ActionGroup *)0;
  vector<Action *>::const_iterator iter;
  Action *ac;
  for(iter=list.begin();iter!=list.end();++iter) {
    ac = (*iter)->clone(grouplist);
    if (ac != (Action *)0) {
      if (res == (ActionGroup *)0)
	res = new ActionRestartGroup(flags,getName(),maxrestarts);
      res->addAction(ac);
    }
  }
  return res;
}

void ActionRestartGroup::reset(Funcdata &data)

{
  curstart = 0;
  ActionGroup::reset(data);
}

int4 ActionRestartGroup::apply(Funcdata &data)

{
  int4 res;

  if (curstart == -1) return 0;	// Already completed
  for(;;) {
    res = ActionGroup::apply(data);
    if (res != 0) return res;
    if (!data.hasRestartPending()) {
      curstart = -1;
      return 0;
    }
    if (data.isJumptableRecoveryOn()) // Don't restart within jumptable recovery
      return 0;
    curstart += 1;
    if (curstart > maxrestarts) {
      data.warningHeader("Exceeded maximum restarts with more pending");
      curstart = -1;
      return 0;
    }
    data.getArch()->clearAnalysis(&data);

    // Reset everything but ourselves
    vector<Action *>::iterator iter;
    for(iter=list.begin();iter!=list.end();++iter)
      (*iter)->reset(data);	// Reset each subrule
    status = status_start;
  }
}

#ifdef OPACTION_DEBUG
bool ActionGroup::turnOnDebug(const string &nm)

{
  if (Action::turnOnDebug(nm))
    return true;
  vector<Action *>::iterator iter;
  for(iter = list.begin();iter!=list.end();++iter)
    if ((*iter)->turnOnDebug(nm))
      return true;
  return false;
}

bool ActionGroup::turnOffDebug(const string &nm)

{
  if (Action::turnOffDebug(nm))
    return true;
  vector<Action *>::iterator iter;
  for(iter = list.begin();iter!=list.end();++iter)
    if ((*iter)->turnOffDebug(nm))
      return true;
  return false;
}
#endif

void ActionGroup::printStatistics(ostream &s) const

{
  Action::printStatistics(s);
  vector<Action *>::const_iterator iter;
  for(iter = list.begin();iter!=list.end();++iter)
    (*iter)->printStatistics(s);
}

/// \param g is the groupname to which \b this Rule belongs
/// \param fl is the set of properties
/// \param nm is the name of the Rule
Rule::Rule(const string &g,uint4 fl,const string &nm)

{
  flags = fl;
  name = nm;
  breakpoint = 0;
  basegroup = g;
  count_tests = 0;
  count_apply = 0;
}

/// This method is called whenever \b this Rule applies. If warnings have been
/// enabled for the Rule via turnOnWarnings(), this method will print a message
/// indicating the Rule has been applied.  Even with repeat calls, the message
/// will only be printed once (until reset() is called)
/// \param glb is the Architecture holding the console to print to
void Rule::issueWarning(Architecture *glb)

{
  if ((flags&(warnings_on|warnings_given)) == warnings_on) {
    flags |= warnings_given;
    glb->printMessage("WARNING: Applied rule "+name);
  }
}

/// Any state that is specific to a particular function is cleared by this method.
/// This method can be used to initialize a Rule based on a new function it will apply to
/// \param data is the \e new function about to be transformed
void Rule::reset(Funcdata &data)

{
  flags &= ~warnings_given;	// Indicate that warning has not yet been given
}

/// Counts of when this Rule has been attempted/applied are reset to zero.
/// Derived Rules may reset their own statistics.
void Rule::resetStats(void)

{
  count_tests = 0;
  count_apply = 0;
}

#ifdef OPACTION_DEBUG
/// If \b this Rule has the given name, then enable debugging.
/// \param nm is the given name to match
/// \return true if debugging was enabled
bool Rule::turnOnDebug(const string &nm)

{
  if (nm == name) {
    flags |= rule_debug;
    return true;
  }
  return false;
}

/// If \b this Rule has the given name, then disable debugging.
/// \param nm is the given name to match
/// \return true if debugging was disabled
bool Rule::turnOffDebug(const string &nm)

{
  if (nm == name) {
    flags &= ~rule_debug;
    return true;
  }
  return false;
}
#endif

/// Print the accumulated counts associated with applying this Rule to stream.
/// This method is intended for console mode debugging. Derived Rules may
/// override this to display their own statistics.
/// \param s is the output stream
void Rule::printStatistics(ostream &s) const

{
  s << name << dec << " Tested=" << count_tests << " Applied=" << count_apply << endl;
}

/// Populate the given array with all possible OpCodes this Rule might apply to.
/// By default, this method returns all possible OpCodes
/// \param oplist is the array to populate
void Rule::getOpList(vector<uint4> &oplist) const

{
  uint4 i;

  for(i=0;i<CPUI_MAX;++i)
    oplist.push_back(i);
}

/// This method is called every time the Rule successfully applies. If it returns
/// \b true, this indicates to the system that an action breakpoint has occurred.
/// \return true if an action breakpoint should occur because of this Rule
bool Rule::checkActionBreak(void)

{
  if ((breakpoint&(Action::break_action|Action::tmpbreak_action))!=0) {
    breakpoint &= ~(Action::tmpbreak_action); // Clear temporary breakpoint
    return true;		// Breakpoint was active
  }
  return false;			// Breakpoint was not active
}

ActionPool::~ActionPool(void)

{
  vector<Rule *>::iterator iter;

  for(iter=allrules.begin();iter!=allrules.end();++iter)
    delete *iter;
}

/// This method should only be invoked during construction of this ActionPool
/// A single Rule is added to the pool. The Rule's OpCode is inspected by this method.
/// \param rl is the Rule to add
void ActionPool::addRule(Rule *rl)

{
  vector<uint4> oplist;
  vector<uint4>::iterator iter;

  // Path 3: honor the optional rule blocklist for never-fires elimination.
  // The rule is still registered (so cloning, stat printout, etc. work) but
  // marked disabled so apply paths skip it via the existing isDisabled() gate.
  const std::set<std::string> &blocklist = getRuleBlocklist();
  if (!blocklist.empty() && blocklist.count(rl->getName()) != 0)
    rl->setDisable();

  allrules.push_back(rl);

  rl->getOpList(oplist);
  for(iter=oplist.begin();iter!=oplist.end();++iter)
    perop[*iter].push_back(rl);	// Add rule to list for each op it registers for
}

int4 ActionPool::print(ostream &s,int4 num,int4 depth) const

{
  vector<Rule *>::const_iterator iter;
  Rule *rl;
  int4 i;

  num = Action::print(s,num,depth);
  s << endl;
  depth += 1;
  for(iter=allrules.begin();iter!=allrules.end();++iter) {
    rl = *iter;
    s << setw(4) << dec << num;
    s << (char) ( rl->isDisabled() ? 'D' : ' ');
    s << (char) ( ((rl->getBreakPoint()&(break_action|tmpbreak_action))!=0) ? 'A' : ' ');
    for(i=0;i<depth*5+2;++i)
      s << ' ';
    s << rl->getName();
    s << endl;
    num += 1;
  }
  return num;
}

void ActionPool::printState(ostream &s) const

{
  PcodeOp *op;

  Action::printState(s);
  if (status==status_mid) {
    op = (*op_state).second;
    s << ' ' << op->getSeqNum();
  }
}

Rule *ActionPool::getSubRule(const string &specify)

{
  string token,remain;
  next_specifyterm(token,remain,specify);
  if (name == token) {
    if (remain.empty()) return (Rule *)0; // Match, but not a rule
  }
  else
    remain = specify;		// Still have to match entire specify

  vector<Rule *>::iterator iter;
  Rule *lastrule = (Rule *)0;
  int4 matchcount = 0;
  for(iter=allrules.begin();iter!=allrules.end();++iter) {
    Rule *testrule = *iter;
    if (testrule->getName() == remain) {
      lastrule = testrule;
      matchcount += 1;
      if (matchcount > 1) return (Rule *)0;
    }
  }
  return lastrule;
}

/// This method attempts to apply each Rule to the current PcodeOp
/// Action breakpoints are checked if the Rule successfully applies.
/// 0 is returned for no breakpoint, -1 if a breakpoint occurs.
/// If a breakpoint did occur, an additional call to processOp() will
/// pick up where it left off before the breakpoint. The PcodeOp iterator is advanced.
/// \param op is the current PcodeOp
/// \param data is the function being transformed
/// \return 0 if no breakpoint, -1 otherwise
int4 ActionPool::processOp(PcodeOp *op,Funcdata &data)

{
  Rule *rl;
  int4 res;
  uint4 opc;

  if (op->isDead()) {
    op_state++;
    data.opDeadAndGone(op);
    rule_index = 0;
    return 0;
  }
  opc = op->code();
  while(rule_index < perop[opc].size()) {
    rl = perop[opc][rule_index++];
    if (rl->isDisabled()) continue;
#ifdef OPACTION_DEBUG
    data.debugActivate();
#endif
    rl->count_tests += 1;
    res = rl->applyOp(op,data);
    if (getScopeStatsEnabled()) {
      int4 b = scopeBucket(rl->getMutationScope());
      scopeTests[b].fetch_add(1, std::memory_order_relaxed);
      if (res > 0) scopeFires[b].fetch_add(1, std::memory_order_relaxed);
    }
    recordRuleResult(rl, res);
#ifdef OPACTION_DEBUG
    data.debugModPrint(rl->getName());
#endif
    if (res>0) {
      rl->count_apply += 1;
      count += res;
      data.bumpIrModCount();
      rl->issueWarning(data.getArch()); // Check if we need to issue a warning
      if (rl->checkActionBreak())
        return -1;
#ifdef OPACTION_DEBUG
      if (data.debugBreak()) {
	data.debugHandleBreak();
	return -1;
      }
#endif
      if (op->isDead()) break;
      if (opc != op->code()) {	// Set of rules to apply to this op has changed
        opc = op->code();
        rule_index = 0;
      }
    }
    else if (opc != op->code()) {
      data.getArch()->printMessage("ERROR: Rule " + rl->getName() + " changed op without returning result of 1!");
      opc = op->code();
      rule_index = 0;
    }
  }
  op_state++;
  rule_index = 0;

  return 0;
}

int4 ActionPool::apply(Funcdata &data)

{
  // ActionPool is the only Action subclass that is purely rule-driven: its
  // entire effect happens via Rule::applyOp() inside processOp(), each of which
  // bumps Funcdata::globalModCount on success.  Therefore, if no rule has
  // fired anywhere in the function since the last successful completion of
  // this ActionPool, no rule can fire here either, and the entire body sweep
  // is provably a no-op.  Skip it without invalidating SHA.
  //
  // Restricted to status_start entries — we do not short-circuit a mid-sweep
  // continuation (status_mid) because that has internal iterator state to drain.
  if (status == status_start && lastSeenModCount != 0 &&
      lastSeenModCount == data.getGlobalModCount()) {
    return 0;
  }

  // Optional two-phase parallel path (env-gated).  Only engages at status_start
  // (full fresh sweep) — does not support mid-sweep resume or breakpoints.
  int4 numWorkers = getIntraParallelWorkers();
  if (numWorkers > 1 && status == status_start) {
    int4 minOps = getIntraParallelMinOps();
    // Estimate op count via map size.  This is O(1).
    int4 opCount = (int4)data.obSize();
    if (opCount >= minOps) {
      // Path 3 dispatcher takes precedence over Path 1 when explicitly enabled.
      if (getBlockParallelEnabled())
        return applyBlockParallel(data,numWorkers);
      return applyParallel(data,numWorkers);
    }
  }

  if (status != status_mid) {
    op_state = data.beginOpAll();	// Initialize the derived action
    rule_index = 0;
  }
  for(;op_state!=data.endOpAll();)
	  if (0!=processOp((*op_state).second,data)) return -1;

  // Successful complete sweep — record modCount for skip-decision next time.
  lastSeenModCount = data.getGlobalModCount();
  return 0;			// Indicate successful completion
}

/// Two-phase parallel sweep:
///   Phase 1 (parallel): partition optree snapshot across N worker threads; each thread
///     calls Rule::canApply() for every applicable (op, rule) pair in its chunk; results
///     are packed into a per-op 64-bit "skip mask" where bit r = 1 means "rule r at this
///     op definitely will not fire — skip it in phase 2".  canApply() is pure (no shared
///     mutation), so reads of Funcdata/Varnode/PcodeOp state are safe to race.
///   Phase 2 (serial): walk ops in original SeqNum order, dispatching rules as in serial
///     processOp() but consulting the skip mask to bypass rules whose canApply returned 0.
///     If a rule fires AND changes the op's opcode, the skip mask is invalidated for the
///     remaining rules of the new opcode (full serial dispatch resumes for that op).
///
/// Correctness: canApply is required to be CONSERVATIVE — returning 0 only when applyOp
/// would definitely return 0 with NO mutation.  Returning 1 (or -1) is always safe and
/// just causes the rule to be tested via the regular serial applyOp in phase 2.
///
/// Determinism: phase 2 walks ops in SeqNum order, same as serial.  Within a single op,
/// rules are dispatched in the same order as serial.  The only difference vs serial is
/// that some rule calls are bypassed (those with canApply=0) — and we have proven by the
/// canApply contract that bypassing them is observationally equivalent to calling them.
int4 ActionPool::applyParallel(Funcdata &data,int4 numWorkers)
{
  // Path 2 instrumentation: build conflict graph on first call per function to gauge potential.
  if (getGraphStatsEnabled()) {
    static thread_local const Funcdata *lastGraphFuncdata = nullptr;
    if (lastGraphFuncdata != &data) {
      lastGraphFuncdata = &data;
      BlockConflictGraph g;
      g.build(data);
      g.colorBlocks();
      int4 nb = g.size();
      int4 ne = g.edgeCount();
      int4 nc = g.getColorCount();
      int4 maxGroupSize = 0;
      for (int4 c = 0; c < nc; ++c) {
	int4 sz = (int4)g.getColorGroup(c).size();
	if (sz > maxGroupSize) maxGroupSize = sz;
      }
      std::fprintf(stderr, "[block-conflict] fn=%s blocks=%d edges=%d colors=%d max_group=%d\n",
		   data.getName().c_str(), nb, ne, nc, maxGroupSize);
      std::fflush(stderr);
    }
  }
  // Phase 0: snapshot all ops into a vector for indexed parallel access in phase 1.
  // The skipMask values are keyed by op pointer (not snapshot index) so that phase 2,
  // which iterates the LIVE optree, can look them up regardless of snapshot index — and
  // ops created during phase 2 (not in the snapshot) simply have no skipMask entry and
  // get full serial dispatch.
  vector<PcodeOp *> allOps;
  allOps.reserve(data.obSize());
  PcodeOpTree::const_iterator it;
  for(it = data.beginOpAll(); it != data.endOpAll(); ++it)
    allOps.push_back((*it).second);
  int4 n = (int4)allOps.size();
  if (n == 0) {
    lastSeenModCount = data.getGlobalModCount();
    return 0;
  }

  vector<uint8> skipMaskVec(n, 0);

  // Phase 1: parallel canApply.  Each thread writes to a disjoint range of skipMaskVec —
  // no synchronization needed.  Reads of PcodeOp/Varnode/Funcdata are pure
  // (canApply contract requires no mutation), so concurrent reads are safe.
  //
  // Inline fast-path: for small workloads, skip thread dispatch entirely.  The mutex+
  // condvar overhead of 4-way thread submit/wait is ~500-1000µs; chunks under
  // INLINE_THRESHOLD ops × rules are not worth parallelizing.
  auto computeMaskRange = [this,&allOps,&skipMaskVec,&data](int4 start, int4 end) {
    for(int4 i = start; i < end; ++i) {
      PcodeOp *op = allOps[i];
      if (op->isDead()) continue;
      uint4 opc = op->code();
      const vector<Rule *> &rules = perop[opc];
      int4 nrules = (int4)rules.size();
      if (nrules > 64) nrules = 64;	// bitmask capacity
      uint8 mask = 0;
      for(int4 r = 0; r < nrules; ++r) {
	Rule *rl = rules[r];
	if (rl->isDisabled()) continue;
	if (!rl->hasCanApply()) continue;	// avoid virtual call for rules without override
	int4 can = rl->canApply(op,data);
	if (can == 0) mask |= ((uint8)1 << r);
      }
      skipMaskVec[i] = mask;
    }
  };

  // Threshold: rough estimate of when parallel dispatch breaks even.  At ~50ns per
  // canApply call and ~5 rules with canApply per op, per-op work is ~250ns.  Thread
  // dispatch overhead per chunk is ~50µs.  Break-even at ~50µs / 250ns = ~200 ops/chunk.
  // We need at least 200×numWorkers ops total to amortize.
  const int4 INLINE_THRESHOLD = 200 * numWorkers;
  if (n < INLINE_THRESHOLD) {
    computeMaskRange(0, n);
  }
  else {
    ThreadPool &pool = ThreadPool::getInstance(numWorkers);
    int4 actualWorkers = std::min(numWorkers,n);
    int4 chunkSize = (n + actualWorkers - 1) / actualWorkers;
    for(int4 t = 0; t < actualWorkers; ++t) {
      int4 start = t * chunkSize;
      int4 end = std::min(n, start + chunkSize);
      pool.submit([&computeMaskRange,start,end]() { computeMaskRange(start,end); });
    }
    pool.waitAll();
  }

  // Phase 2: serial dispatch over the phase-1 snapshot.  This skips ops created
  // during phase 2 in this same call (they'll be picked up next outer-loop iteration
  // when modCount changes trigger another apply).  This makes the parallel path
  // produce semantically-equivalent but not bit-identical output vs serial —
  // intra-pass cascade order differs, leading to different variable naming late in
  // the pipeline.  Accepts vector-indexed mask lookup (O(1)) for speed.
  for(int4 i = 0; i < n; ++i) {
    PcodeOp *op = allOps[i];

    if (op->isDead()) {
      data.opDeadAndGone(op);
      continue;
    }
    uint8 mask = skipMaskVec[i];

    uint4 opc = op->code();
    int4 rule_idx = 0;
    while(rule_idx < (int4)perop[opc].size()) {
      Rule *rl = perop[opc][rule_idx];
      if (rl->isDisabled()) { rule_idx += 1; continue; }
      // Skip if canApply said no AND opcode hasn't changed since phase 1
      if (rule_idx < 64 && (mask & ((uint8)1 << rule_idx)) != 0) {
	rule_idx += 1;
	continue;
      }
      rl->count_tests += 1;
      int4 res = rl->applyOp(op,data);
      if (getScopeStatsEnabled()) {
	int4 b = scopeBucket(rl->getMutationScope());
	scopeTests[b].fetch_add(1, std::memory_order_relaxed);
	if (res > 0) scopeFires[b].fetch_add(1, std::memory_order_relaxed);
      }
      recordRuleResult(rl, res);
      if (res > 0) {
	rl->count_apply += 1;
	count += res;
	data.bumpIrModCount();
	rl->issueWarning(data.getArch());
	if (rl->checkActionBreak()) {
	  // Parallel mode does not support resumable breakpoints; abort the sweep.
	  return -1;
	}
	if (op->isDead()) break;
	if (opc != op->code()) {
	  opc = op->code();
	  rule_idx = 0;
	  mask = 0;	// invalidate canApply filter since opcode has changed
	  continue;
	}
      }
      else if (opc != op->code()) {
	data.getArch()->printMessage("ERROR: Rule " + rl->getName() + " changed op without returning result of 1!");
	opc = op->code();
	rule_idx = 0;
	mask = 0;
	continue;
      }
      rule_idx += 1;
    }
  }

  lastSeenModCount = data.getGlobalModCount();
  return 0;
}

/// \brief Path 3 block-DAG parallel dispatcher with color-aware canApply.
///
/// Partitions the function's ops by the block-conflict-graph color of their
/// containing BasicBlock and runs the canApply filter (phase 1) in parallel
/// across color groups, then dispatches applyOp (phase 2) serially in
/// color-major order with the skip mask consulted.
///
/// Compared to applyParallel which strides the canApply phase by raw op
/// index, color-aligned chunking keeps def-use locality within a worker
/// (a worker reading op X's input Varnodes is likely to read other Varnodes
/// from the same color group's block(s)).  It also enables a future P3-N
/// to upgrade phase 2 to actual parallel applyOp once Funcdata is made
/// thread-safe — the partition is already prepared.
///
/// Correctness: same contract as applyParallel.  canApply is pure-read;
/// concurrent reads of Funcdata/Varnode/PcodeOp state are safe.  Phase 2
/// is serial, so applyOp mutation is single-threaded.  Op visit order is
/// {color, SeqNum} rather than pure SeqNum, but the ActionPool sweeps to
/// quiescence so cross-color firings are picked up on subsequent sweeps.
int4 ActionPool::applyBlockParallel(Funcdata &data,int4 numWorkers)
{
  // Build conflict graph + coloring once per call.
  BlockConflictGraph graph;
  graph.build(data);
  graph.colorBlocks();
  int4 numColors = graph.getColorCount();
  if (numColors <= 0) {
    // Degenerate: no blocks or no edges.  Fall back to Path 1 behavior.
    return applyParallel(data, numWorkers);
  }

  // Phase 0: snapshot ops in color-major order, plus a loose bucket for
  // ops without a valid parent block.  colorStart[c] is the index in allOps
  // where color c begins; allOps[colorStart[c] .. colorStart[c+1]-1] are
  // the ops of color c, all reachable independently from any other color.
  int4 totalColors = numColors + 1;	// +1 for loose bucket
  vector<vector<PcodeOp *>> opsByColor(totalColors);
  int4 looseBucket = numColors;
  PcodeOpTree::const_iterator it;
  for (it = data.beginOpAll(); it != data.endOpAll(); ++it) {
    PcodeOp *op = (*it).second;
    BlockBasic *bb = op->getParent();
    int4 c = (bb != (BlockBasic *)0) ? graph.colorOf(bb->getIndex()) : -1;
    if (c < 0 || c >= numColors)
      opsByColor[looseBucket].push_back(op);
    else
      opsByColor[c].push_back(op);
  }

  vector<PcodeOp *> allOps;
  allOps.reserve(data.obSize());
  vector<int4> colorStart(totalColors + 1, 0);
  for (int4 c = 0; c < totalColors; ++c) {
    colorStart[c] = (int4)allOps.size();
    for (size_t i = 0; i < opsByColor[c].size(); ++i)
      allOps.push_back(opsByColor[c][i]);
  }
  colorStart[totalColors] = (int4)allOps.size();
  int4 n = (int4)allOps.size();
  if (n == 0) {
    lastSeenModCount = data.getGlobalModCount();
    return 0;
  }

  vector<uint8> skipMaskVec(n, 0);

  // Phase 1: compute canApply mask, parallelized across color ranges.
  auto computeMaskColorRange = [this,&allOps,&skipMaskVec,&colorStart,&data](int4 startC, int4 endC) {
    for (int4 c = startC; c < endC; ++c) {
      for (int4 i = colorStart[c]; i < colorStart[c+1]; ++i) {
	PcodeOp *op = allOps[i];
	if (op->isDead()) continue;
	uint4 opc = op->code();
	const vector<Rule *> &rules = perop[opc];
	int4 nrules = (int4)rules.size();
	if (nrules > 64) nrules = 64;
	uint8 mask = 0;
	for (int4 r = 0; r < nrules; ++r) {
	  Rule *rl = rules[r];
	  if (rl->isDisabled()) continue;
	  if (!rl->hasCanApply()) continue;
	  if (rl->canApply(op,data) == 0) mask |= ((uint8)1 << r);
	}
	skipMaskVec[i] = mask;
      }
    }
  };

  // Inline if too small to amortize dispatch overhead, or only one color.
  const int4 INLINE_THRESHOLD = 200 * numWorkers;
  if (n < INLINE_THRESHOLD || totalColors <= 1) {
    computeMaskColorRange(0, totalColors);
  } else {
    ThreadPool &pool = ThreadPool::getInstance(numWorkers);
    int4 colorsPerWorker = (totalColors + numWorkers - 1) / numWorkers;
    int4 actualWorkers = (totalColors + colorsPerWorker - 1) / colorsPerWorker;
    for (int4 t = 0; t < actualWorkers; ++t) {
      int4 startC = t * colorsPerWorker;
      int4 endC = std::min(totalColors, startC + colorsPerWorker);
      pool.submit([&computeMaskColorRange, startC, endC]() {
	computeMaskColorRange(startC, endC);
      });
    }
    pool.waitAll();
  }

  // Helper: process one op against a scope-filtered rule subset.
  //  onlyOpScope=true  → only scope_op_only rules (used by phase 2a parallel)
  //  onlyOpScope=false → only non-scope_op_only rules (used by phase 2b after 2a)
  // Returns count of rule fires (>=0) or -1 to request action-break abort.
  auto processOpFiltered = [this,&data](PcodeOp *op, uint8 maskIn, bool onlyOpScope) -> int4 {
    int4 localCount = 0;
    uint8 mask = maskIn;
    uint4 opc = op->code();
    int4 rule_idx = 0;
    while (rule_idx < (int4)perop[opc].size()) {
      Rule *rl = perop[opc][rule_idx];
      if (rl->isDisabled()) { rule_idx += 1; continue; }
      bool isOpOnly = (rl->getMutationScope() == (uint4)Rule::scope_op_only);
      if (onlyOpScope != isOpOnly) { rule_idx += 1; continue; }
      if (rule_idx < 64 && (mask & ((uint8)1 << rule_idx)) != 0) {
	rule_idx += 1;
	continue;
      }
      rl->count_tests += 1;
      int4 res = rl->applyOp(op, data);
      if (getScopeStatsEnabled()) {
	int4 b = scopeBucket(rl->getMutationScope());
	scopeTests[b].fetch_add(1, std::memory_order_relaxed);
	if (res > 0) scopeFires[b].fetch_add(1, std::memory_order_relaxed);
      }
      recordRuleResult(rl, res);
      if (res > 0) {
	rl->count_apply += 1;
	localCount += res;
	data.bumpIrModCount();
	rl->issueWarning(data.getArch());
	if (rl->checkActionBreak()) return -1;
	if (op->isDead()) break;
	if (opc != op->code()) {
	  opc = op->code();
	  rule_idx = 0;
	  mask = 0;
	  continue;
	}
      }
      else if (opc != op->code()) {
	data.getArch()->printMessage("ERROR: Rule " + rl->getName() + " changed op without returning result of 1!");
	opc = op->code();
	rule_idx = 0;
	mask = 0;
	continue;
      }
      rule_idx += 1;
    }
    return localCount;
  };

  bool trueParallel = getTrueParallelEnabled() && (numColors > 1) && (numWorkers > 1);

  // Snapshot original opcode per allOps slot so phase 2b can detect when phase 2a
  // changed it (the cached skip mask refers to the original opcode and becomes
  // meaningless after an opcode swap; phase 2b must invalidate mask in that case).
  vector<uint4> origOpcode;
  if (trueParallel) {
    origOpcode.resize(n);
    for (int4 i = 0; i < n; ++i)
      origOpcode[i] = allOps[i]->isDead() ? 0xffffffff : allOps[i]->code();
  }

  // Phase 2a (parallel, optional): scope_op_only rules across color groups.
  // scope_op_only rules mutate only the dispatched op itself (and Funcdata pool
  // allocators) — no descendants, no block topology — so different colors never
  // contend on op state.  Funcdata mutators acquire L1 poolMutex; Varnode
  // descend list ops acquire L2 descendMutex; mod-counters are atomic (L3).
  if (trueParallel) {
    std::atomic<int4> count2a(0);
    std::atomic<bool> breakReq(false);
    ThreadPool &pool = ThreadPool::getInstance(numWorkers);
    int4 colorsPerWorker = (numColors + numWorkers - 1) / numWorkers;
    int4 actualWorkers = (numColors + colorsPerWorker - 1) / colorsPerWorker;
    auto workerFn = [&,this](int4 startC, int4 endC) {
      for (int4 c = startC; c < endC; ++c) {
	if (breakReq.load(std::memory_order_relaxed)) return;
	for (int4 i = colorStart[c]; i < colorStart[c+1]; ++i) {
	  PcodeOp *op = allOps[i];
	  if (op->isDead()) continue;
	  int4 r = processOpFiltered(op, skipMaskVec[i], true);
	  if (r < 0) { breakReq.store(true, std::memory_order_relaxed); return; }
	  if (r > 0) count2a.fetch_add(r, std::memory_order_relaxed);
	}
      }
    };
    for (int4 t = 0; t < actualWorkers; ++t) {
      int4 startC = t * colorsPerWorker;
      int4 endC = std::min(numColors, startC + colorsPerWorker);
      pool.submit([&workerFn, startC, endC]() { workerFn(startC, endC); });
    }
    pool.waitAll();
    if (breakReq.load()) return -1;
    count += count2a.load();
  }

  // Phase 2b: serial dispatch in color-major order, with skip mask.
  // If phase 2a ran, skip scope_op_only rules here.  Otherwise dispatch all rules.
  // When a rule fires AND changes the op's opcode, the skip mask for the new
  // opcode is unknown, so we invalidate it (mask = 0) and let serial dispatch
  // fall through to full rule iteration.
  for (int4 i = 0; i < n; ++i) {
    PcodeOp *op = allOps[i];
    if (op->isDead()) {
      data.opDeadAndGone(op);
      continue;
    }
    uint4 opc = op->code();
    // If phase 2a changed this op's opcode, the original skip mask is for the
    // old opcode's rule list and is meaningless for the new opcode's rules.
    uint8 mask = (trueParallel && opc != origOpcode[i]) ? 0 : skipMaskVec[i];

    int4 rule_idx = 0;
    while (rule_idx < (int4)perop[opc].size()) {
      Rule *rl = perop[opc][rule_idx];
      if (rl->isDisabled()) { rule_idx += 1; continue; }
      if (trueParallel && rl->getMutationScope() == (uint4)Rule::scope_op_only) {
	rule_idx += 1; continue;	// handled by phase 2a
      }
      if (rule_idx < 64 && (mask & ((uint8)1 << rule_idx)) != 0) {
	rule_idx += 1;
	continue;
      }
      rl->count_tests += 1;
      int4 res = rl->applyOp(op, data);
      if (getScopeStatsEnabled()) {
	int4 b = scopeBucket(rl->getMutationScope());
	scopeTests[b].fetch_add(1, std::memory_order_relaxed);
	if (res > 0) scopeFires[b].fetch_add(1, std::memory_order_relaxed);
      }
      recordRuleResult(rl, res);
      if (res > 0) {
	rl->count_apply += 1;
	count += res;
	data.bumpIrModCount();
	rl->issueWarning(data.getArch());
	if (rl->checkActionBreak()) return -1;
	if (op->isDead()) break;
	if (opc != op->code()) {
	  opc = op->code();
	  rule_idx = 0;
	  mask = 0;	// opcode changed → skip mask is stale
	  continue;
	}
      }
      else if (opc != op->code()) {
	data.getArch()->printMessage("ERROR: Rule " + rl->getName() + " changed op without returning result of 1!");
	opc = op->code();
	rule_idx = 0;
	mask = 0;
	continue;
      }
      rule_idx += 1;
    }
  }
  // suppress unused-lambda warning if neither path uses it (it's referenced in 2a only)
  (void)processOpFiltered;

  lastSeenModCount = data.getGlobalModCount();
  return 0;
}

void ActionPool::clearBreakPoints(void)

{
  vector<Rule *>::const_iterator iter;
  for(iter=allrules.begin();iter!=allrules.end();++iter)
    (*iter)->clearBreakPoints();
  Action::clearBreakPoints();
}

Action *ActionPool::clone(const ActionGroupList &grouplist) const

{
  ActionPool *res = (ActionPool *)0;
  vector<Rule *>::const_iterator iter;
  Rule *rl;
  for(iter=allrules.begin();iter!=allrules.end();++iter) {
    rl = (*iter)->clone(grouplist);
    if (rl != (Rule *)0) {
      if (res == (ActionPool *)0)
	res = new ActionPool(flags,getName());
      res->addRule(rl);
    }
  }
  return res;
}

void ActionPool::reset(Funcdata &data)

{
  vector<Rule *>::iterator iter;

  Action::reset(data);
  for(iter=allrules.begin();iter!=allrules.end();++iter)
    (*iter)->reset(data);
}

void ActionPool::resetStats(void)

{
  vector<Rule *>::iterator iter;

  Action::resetStats();
  for(iter=allrules.begin();iter!=allrules.end();++iter)
    (*iter)->resetStats();
}

#ifdef OPACTION_DEBUG
bool ActionPool::turnOnDebug(const string &nm)

{
  vector<Rule *>::iterator iter;

  if (Action::turnOnDebug(nm))
    return true;
  for(iter=allrules.begin();iter!=allrules.end();++iter)
    if ((*iter)->turnOnDebug(nm))
      return true;
  return false;
}

bool ActionPool::turnOffDebug(const string &nm)

{
  vector<Rule *>::iterator iter;

  if (Action::turnOffDebug(nm))
    return true;
  for(iter=allrules.begin();iter!=allrules.end();++iter)
    if ((*iter)->turnOffDebug(nm))
      return true;
  return false;
}
#endif

void ActionPool::printStatistics(ostream &s) const

{
  vector<Rule *>::const_iterator iter;

  Action::printStatistics(s);
  for(iter=allrules.begin();iter!=allrules.end();++iter)
    (*iter)->printStatistics(s);
}

const char ActionDatabase::universalname[] = "universal";

ActionDatabase::~ActionDatabase(void)

{
  map<string,Action *>::iterator iter;
  for(iter = actionmap.begin();iter!=actionmap.end();++iter)
    delete (*iter).second;
}

/// Clear out (possibly altered) root Actions. Reset the default groups.
/// Set the default root action "decompile"
void ActionDatabase::resetDefaults(void)

{
  Action *universalAction = (Action *)0;
  map<string,Action *>::iterator iter;
  iter = actionmap.find(universalname);
  if (iter != actionmap.end())
    universalAction = (*iter).second;
  for(iter = actionmap.begin();iter!=actionmap.end();++iter) {
    Action *curAction = (*iter).second;
    if (curAction != universalAction)
      delete curAction;		// Clear out any old (modified) root actions
  }
  actionmap.clear();
  registerAction(universalname, universalAction);

  buildDefaultGroups();
  setCurrent("decompile");	// The default root action
}

const ActionGroupList &ActionDatabase::getGroup(const string &grp) const

{
  map<string,ActionGroupList>::const_iterator iter;

  iter = groupmap.find(grp);
  if (iter == groupmap.end())
    throw LowlevelError("Action group does not exist: "+grp);
  return (*iter).second;
}

/// The Action is specified by name.  A grouplist must already exist for this name.
/// If the Action doesn't already exist, it will be derived from the \e universal
/// action via this grouplist.
/// \param actname is the name of the \e root Action
Action *ActionDatabase::setCurrent(const string &actname)

{
  currentactname = actname;
  currentact = deriveAction(universalname,actname);
  return currentact;
}


/// A particular group is either added or removed from the grouplist defining
/// a particular \e root Action.  The \e root Action is then (re)derived from the universal
/// \param grp is the name of the \e root Action
/// \param basegrp is name of group (within the grouplist) to toggle
/// \param val is \b true if the group should be added or \b false if it should be removed
/// \return the modified \e root Action
Action *ActionDatabase::toggleAction(const string &grp, const string &basegrp,bool val)

{
  Action *act = getAction(universalname);
  if (val)
    addToGroup(grp,basegrp);
  else
    removeFromGroup(grp,basegrp);
  const ActionGroupList &curgrp(getGroup(grp)); // Group should already exist
  Action *newact = act->clone(curgrp);

  registerAction(grp,newact);

  if (grp == currentactname)
    currentact = newact;

  return newact;
}

/// (Re)set the grouplist for a particular \e root Action.  Do not use this routine
/// to redefine an existing \e root Action.
/// \param grp is the name of the \e root Action
/// \param argv is a list of static char pointers, which must end with a NULL pointer, or a zero length string.
void ActionDatabase::setGroup(const string &grp,const char **argv)

{
  ActionGroupList &curgrp( groupmap[ grp ] );
  curgrp.list.clear();		// Clear out any old members
  for(int4 i=0;;++i) {
    if (argv[i] == (char *)0) break;
    if (argv[i][0] == '\0') break;
    curgrp.list.insert( argv[i] );
  }
  isDefaultGroups = false;
}

/// Copy an existing \e root Action by copying its grouplist, giving it a new name.
/// This is suitable for a copy then modify strategy to create a new \e root Action.
/// Do not use to redefine a \e root Action that has already been instantiated
/// \param oldname is the name of an existing \e root Action
/// \param newname is the name of the copy
void ActionDatabase::cloneGroup(const string &oldname,const string &newname)

{
  const ActionGroupList &curgrp(getGroup(oldname)); // Should already exist
  groupmap[ newname ] = curgrp;	// Copy the group
  isDefaultGroups = false;
}

/// Add a group to the grouplist for a particular \e root Action.
/// Do not use to redefine a \e root Action that has already been instantiated.
/// \param grp is the name of the \e root Action
/// \param basegroup is the group to add
/// \return \b true for a new addition, \b false is the group was already present
bool ActionDatabase::addToGroup(const string &grp, const string &basegroup)

{
  isDefaultGroups = false;
  ActionGroupList &curgrp( groupmap[ grp ] );
  return curgrp.list.insert( basegroup ).second;
}

/// The group is removed from the grouplist of a \e root Action.
/// Do not use to redefine a \e root Action that has already been instantiated.
/// \param grp is the name of the \e root Action
/// \param basegrp is the group to remove
/// \return \b true if the group existed and was removed
bool ActionDatabase::removeFromGroup(const string &grp, const string &basegrp)

{
  isDefaultGroups = false;
  ActionGroupList &curgrp( groupmap[ grp ] );
  return (curgrp.list.erase(basegrp) > 0);
}

/// \param nm is the name of the \e root Action
Action *ActionDatabase::getAction(const string &nm) const

{
  map<string,Action *>::const_iterator iter;
  iter = actionmap.find(nm);
  if (iter == actionmap.end())
    throw LowlevelError("No registered action: "+nm);
  return (*iter).second;
}

/// Internal method for associated a \e root Action name with its Action object.
/// The database takes over memory management of the object.
/// \param nm is the name to register as
/// \param act is the Action object
void ActionDatabase::registerAction(const string &nm,Action *act)

{
  map<string,Action *>::iterator iter;
  iter = actionmap.find(nm);
  if (iter != actionmap.end()) {
    delete (*iter).second;
    (*iter).second = act;
  }
  else {
    actionmap[nm] = act;
  }
}

/// Internal method to build the Action object corresponding to a \e root Action
/// The new Action object is created by selectively cloning components
/// from an existing object based on a grouplist.
/// \param baseaction is the name of the model Action object to derive \e from
/// \param grp is the name of the grouplist steering the clone
Action *ActionDatabase::deriveAction(const string &baseaction, const string &grp)

{
  map<string,Action *>::iterator iter;
  iter = actionmap.find(grp);
  if (iter != actionmap.end())
    return (*iter).second;	// Already derived this action
  
  const ActionGroupList &curgrp(getGroup(grp)); // Group should already exist
  Action *act = getAction(baseaction);
  Action *newact = act->clone( curgrp );

  // Register the action with the name of the group it was derived from
  registerAction(grp,newact);
  return newact;
}

} // End namespace ghidra
