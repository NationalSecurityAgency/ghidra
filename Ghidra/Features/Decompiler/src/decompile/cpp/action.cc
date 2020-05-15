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

#include "coreaction.hh"

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
#ifdef OPACTION_DEBUG
    data.debugModPrint(rl->getName());
#endif
    if (res>0) {
      rl->count_apply += 1;
      count += res;
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
  if (status != status_mid) {
    op_state = data.beginOpAll();	// Initialize the derived action
    rule_index = 0;
  }
  for(;op_state!=data.endOpAll();)
	  if (0!=processOp((*op_state).second,data)) return -1;

  return 0;			// Indicate successful completion
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
