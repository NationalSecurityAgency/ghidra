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
package ghidra.app.plugin.core.analysis;

import java.lang.reflect.InvocationTargetException;
import java.util.*;
import java.util.Stack;
import java.util.concurrent.CountDownLatch;

import javax.swing.JFrame;
import javax.swing.SwingUtilities;

import org.apache.commons.collections4.Factory;
import org.apache.commons.collections4.map.LazyMap;

import docking.widgets.OptionDialog;
import generic.concurrent.GThreadPool;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.*;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;
import ghidra.util.*;
import ghidra.util.bean.opteditor.OptionsVetoException;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.datastruct.PriorityQueue;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

/**
 * AutoAnalysisPlugin
 *
 * Provides support for auto analysis tasks.
 * Manages a pipeline or priority of tasks to run given some event has occurred.
 */
public class AutoAnalysisManager implements DomainObjectListener, DomainObjectClosedListener {

	/**
	 * The name of the shared thread pool that analyzers can uses to do parallel processing.
	 */
	private static final String SHARED_THREAD_POOL_NAME = "Analysis";
	private static final String OPTION_NAME_THREAD_USE = "Max Threads";
	private static final String OPTION_DESCRIPTION_THREAD_USE =
		"Maximum number of threads to use at once for tasks that run in parallel";

	/**
	 * The size of the statically shared analysis thread pool.
	 * <p>
	 * Note: this value is static so that it can be shared by multiple tools.   However, to change
	 * this value, the user does so through the options GUI of the current tool.  This means
	 * that the settings can differ.  In that case, we have to pick which setting to choose.  For
	 * now, let's chooser the higher of the two settings.  This will only be an issue if the user
	 * runs more than one tool, with different option values, during a Ghidra run (same JVM
	 * instance).
	 */
	private static int analysisSharedThreadPoolSize = SystemUtilities.getDefaultThreadPoolSize();

	private static Map<Program, AutoAnalysisManager> managerMap = new WeakHashMap<>();

	private static final Factory<WeakSet<PluginTool>> SET_FACTORY =
		() -> WeakDataStructureFactory.createCopyOnWriteWeakSet();

	private static Map<Program, WeakSet<PluginTool>> toolMap =
		LazyMap.lazyMap(new WeakHashMap<Program, WeakSet<PluginTool>>(), SET_FACTORY);

	private volatile Program program;
	private DefaultDataTypeManagerService service = null;

	private AnalysisTaskList byteTasks;
	private AnalysisTaskList functionTasks;
	private AnalysisTaskList functionModifierChangedTasks;
	private AnalysisTaskList functionSignatureChangedTasks;
	private AnalysisTaskList instructionTasks;
	private AnalysisTaskList dataTasks;
	private AnalysisTaskList[] taskArray;

	// locations during one analysis run that have been disassembly targets
	// these should be protected from things like clearing flow damage
	private AddressSet protectedLocations = new AddressSet();

	//private Integer currentTaskPriority = null;
	//private Stack<Integer> taskPriorityStack = new Stack<Integer>();

	private PriorityQueue<BackgroundCommand> queue = new PriorityQueue<>();
	private Map<String, Long> timedTasks = new HashMap<>();
	// used for testing and performance monitoring; accessed via reflection
	private Map<String, Long> cumulativeTasks = new HashMap<>();

	private boolean backgroundAnalysisPending = false;
	private Thread analysisThread;
	private AnalysisTaskWrapper activeTask;
	private Stack<AnalysisTaskWrapper> yieldedTasks = new Stack<>();

	/**
	 * This variable is a poorly defined concept.  Essentially, this value is <b>intended</b> to
	 * be set to whatever tool launched analysis.  This is fine for single-tool use cases.
	 * However, when the same program is open in multiple tools, this becomes odd when analysis
	 * is run from different tools at different points in time.  Doing this leads to unpredictable
	 * behavior.  However, this is what we currently have to live with in order to make sure
	 * that analysis happens inside of whatever tool the user triggers the analysis action.
	 */
	private PluginTool analysisTool;

	boolean debugOn = false;
	private int totalTaskTime = 0;

	private volatile boolean ignoreChanges;
	private boolean isEnabled = true; // used by testing via introspection

	private MessageLog log = new MessageLog();

	private List<AutoAnalysisManagerListener> listeners = new ArrayList<>();

	private EventQueueID eventQueueID;

	/**
	 * Creates a new instance of the plugin giving it the tool that
	 * it will work in.
	 */
	private AutoAnalysisManager(Program program) {
		this.program = program;
		eventQueueID = program.createPrivateEventQueue(this, 500);
		program.addCloseListener(this);
		initializeAnalyzers();
	}

	private void initializeAnalyzers() {
		byteTasks = new AnalysisTaskList(this, AnalyzerType.BYTE_ANALYZER.getName());
		functionTasks = new AnalysisTaskList(this, AnalyzerType.FUNCTION_ANALYZER.getName());
		functionModifierChangedTasks =
			new AnalysisTaskList(this, AnalyzerType.FUNCTION_MODIFIERS_ANALYZER.getName());
		functionSignatureChangedTasks =
			new AnalysisTaskList(this, AnalyzerType.FUNCTION_SIGNATURES_ANALYZER.getName());
		instructionTasks = new AnalysisTaskList(this, AnalyzerType.INSTRUCTION_ANALYZER.getName());
		dataTasks = new AnalysisTaskList(this, AnalyzerType.DATA_ANALYZER.getName());

		taskArray = new AnalysisTaskList[] { byteTasks, instructionTasks, functionTasks,
			functionModifierChangedTasks, functionSignatureChangedTasks, dataTasks };

		List<Analyzer> analyzers = ClassSearcher.getInstances(Analyzer.class);
		for (Analyzer analyzer : analyzers) {
			if (!analyzer.canAnalyze(program)) {
				continue;
			}
			AnalyzerType type = analyzer.getAnalysisType();
			if (type == AnalyzerType.BYTE_ANALYZER) {
				byteTasks.add(analyzer);
			}
			else if (type == AnalyzerType.DATA_ANALYZER) {
				dataTasks.add(analyzer);
			}
			else if (type == AnalyzerType.FUNCTION_ANALYZER) {
				functionTasks.add(analyzer);
			}
			else if (type == AnalyzerType.FUNCTION_MODIFIERS_ANALYZER) {
				functionModifierChangedTasks.add(analyzer);
			}
			else if (type == AnalyzerType.FUNCTION_SIGNATURES_ANALYZER) {
				functionSignatureChangedTasks.add(analyzer);
			}
			else if (type == AnalyzerType.INSTRUCTION_ANALYZER) {
				instructionTasks.add(analyzer);
			}
			else {
				Msg.showError(this, null, "Unknown Analysis Type",
					"Unexpected Analysis type " + type);
			}
		}
		registerOptions();
		initializeOptions();
	}

	public MessageLog getMessageLog() {
		return log;
	}

	public Analyzer getAnalyzer(String analyzerName) {
		for (AnalysisTaskList taskList : taskArray) {
			Iterator<AnalysisScheduler> iterator = taskList.iterator();
			while (iterator.hasNext()) {
				AnalysisScheduler scheduler = iterator.next();
				if (scheduler.getAnalyzer().getName().equals(analyzerName)) {
					return scheduler.getAnalyzer();
				}
			}
		}
		return null;
	}

	/**
	 * @return program this analysis manager is attached to
	 */
	public Program getProgram() {
		return program;
	}

	public void scheduleOneTimeAnalysis(Analyzer analyzer, AddressSetView set) {
		/*when running a one shot analyzer, first check to see
		 *if an analyzer of the same class already exists. if so,
		 *then inherit it's properties.
		 */
		Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
		analyzer.optionsChanged(options.getOptions(analyzer.getName()), getProgram());

		BackgroundCommand cmd = new OneShotAnalysisCommand(analyzer, set, log);
		schedule(cmd, analyzer.getPriority().priority());
	}

	/**
	 * Identify external addresses which need to be analyzed
	 * NOTE: This is a convenience method for blockAdded
	 * @param extAddr external address or null for all externals
	 */
	public void externalAdded(Address extAddr) {
		if (ignoreChanges) {
			return;
		}
		if (extAddr != null) {
			byteTasks.notifyAdded(extAddr);
		}
		else {
			byteTasks.notifyAdded(new AddressSet(AddressSpace.EXTERNAL_SPACE.getMinAddress(),
				AddressSpace.EXTERNAL_SPACE.getMaxAddress()));
		}
	}

	public void blockAdded(AddressSetView set) {
		if (!ignoreChanges && set != null && !set.isEmpty()) {
			byteTasks.notifyAdded(set);
		}
	}

	public void codeDefined(Address addr) {
		if (!ignoreChanges && addr != null) {
			instructionTasks.notifyAdded(addr);
		}
	}

	public void codeDefined(AddressSetView set) {
		if (!ignoreChanges && set != null && !set.isEmpty()) {
			instructionTasks.notifyAdded(set);
		}
	}

	public void dataDefined(AddressSetView set) {
		if (!ignoreChanges && set != null && !set.isEmpty()) {
			dataTasks.notifyAdded(set);
		}
	}

	public void functionDefined(Address addr) {
		if (!ignoreChanges && addr != null) {
			functionTasks.notifyAdded(addr);
		}
	}

	public void functionDefined(AddressSetView set) {
		if (!ignoreChanges && set != null && !set.isEmpty()) {
			functionTasks.notifyAdded(set);
		}
	}

	public void functionModifierChanged(Address addr) {
		if (!ignoreChanges && addr != null) {
			functionModifierChangedTasks.notifyAdded(addr);
		}
	}

	public void functionModifierChanged(AddressSetView set) {
		if (!ignoreChanges && set != null && !set.isEmpty()) {
			functionModifierChangedTasks.notifyAdded(set);
		}
	}

	public void functionSignatureChanged(Address addr) {
		if (!ignoreChanges && addr != null) {
			functionSignatureChangedTasks.notifyAdded(addr);
		}
	}

	public void functionSignatureChanged(AddressSetView set) {
		if (!ignoreChanges && set != null && !set.isEmpty()) {
			functionSignatureChangedTasks.notifyAdded(set);
		}
	}

	/**
	 * Tell analyzers that all the addresses in the set should be re-analyzed when analysis runs.
	 * Invoking this method provides consistency in re-analyzing all or a subset of the existing things in a program.
	 *
	 * NOTE: This will not kick off analysis nor wait, but it will get scheduled.
	 *
	 * @param restrictSet - null to do the entire program, or a set of address to be re-analyzed fully
	 */
	public void reAnalyzeAll(AddressSetView restrictSet) {

		if (restrictSet == null || restrictSet.isEmpty()) {
			externalAdded(null);
			restrictSet = program.getMemory(); // process entire program
		}

		blockAdded(restrictSet);

		if (program.getListing().getNumInstructions() != 0) {
			codeDefined(restrictSet);
		}

		// Note: This is a new call from previous versions.
		if (program.getListing().getNumDefinedData() != 0) {
			dataDefined(restrictSet);
		}

		// Note: This is a new call from previous versions.
		if (program.getFunctionManager().getFunctions(true).hasNext()) {
			functionDefined(restrictSet);
			functionSignatureChanged(restrictSet);
		}
	}

	public void setDebug(boolean b) {
		debugOn = b;
	}

	private boolean isFunctionModifierChange(ProgramChangeRecord functionChangeRecord) {
		int subType = functionChangeRecord.getSubEventType();
		return subType == ChangeManager.FUNCTION_CHANGED_THUNK ||
			subType == ChangeManager.FUNCTION_CHANGED_INLINE ||
			subType == ChangeManager.FUNCTION_CHANGED_NORETURN ||
			subType == ChangeManager.FUNCTION_CHANGED_CALL_FIXUP ||
			subType == ChangeManager.FUNCTION_CHANGED_PURGE;
	}

	private boolean isFunctionSignatureChange(ProgramChangeRecord functionChangeRecord) {
		int subType = functionChangeRecord.getSubEventType();
		return subType == ChangeManager.FUNCTION_CHANGED_PARAMETERS ||
			subType == ChangeManager.FUNCTION_CHANGED_RETURN;
	}

	@Override
	public void domainObjectClosed() {
		dispose();
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		if (program == null) {
			return;
		}
		else if (program.isClosed()) {
			cancelQueuedTasks();
			dispose();
			return;
		}

		if (ignoreChanges) {
			return;
		}

		int eventCnt = ev.numRecords();
		boolean optionsChanged = false;
		for (int i = 0; i < eventCnt; ++i) {
			DomainObjectChangeRecord doRecord = ev.getChangeRecord(i);
			if (doRecord.getEventType() == ChangeManager.DOCR_LANGUAGE_CHANGED) {
				initializeAnalyzers();
			}

			int eventType = doRecord.getEventType();
			ProgramChangeRecord pcr;

			switch (eventType) {
				case DomainObject.DO_OBJECT_RESTORED:
				case DomainObject.DO_PROPERTY_CHANGED:
					if (!optionsChanged) {
						initializeOptions();
						Preferences.store();
						optionsChanged = true;
					}
					break;
				// TODO: Add Symbol analyzer type
//				case ChangeManager.DOCR_SYMBOL_ADDED:
//				case ChangeManager.DOCR_SYMBOL_RENAMED:
//					pcr = (ProgramChangeRecord) doRecord;
//					// if a function is created using the current name, don't throw symbol added/renamed
//					// split variable changed/added from SYMBOL added - change record is already different
//					if (pcr.getObject() != null && pcr.getObject() instanceof VariableSymbolDB) {
//						break;
//					}
//					Symbol sym = null;
//					Object newValue = pcr.getNewValue();
//					if (newValue != null && newValue instanceof Symbol) {
//						sym = (Symbol) newValue;
//					} else if (pcr.getObject() != null && pcr.getObject() instanceof Symbol) {
//						sym = (Symbol) pcr.getObject();
//					}
//					if (sym == null) {
//						break;
//					}
//					SymbolType symbolType = sym.getSymbolType();
//					if ((symbolType == SymbolType.CODE || symbolType == SymbolType.FUNCTION) && sym.getSource() != SourceType.DEFAULT) {
//						symbolTasks.notifyAdded(sym.getAddress());
//					}
//					break;
				case ChangeManager.DOCR_FUNCTION_CHANGED:
					pcr = (ProgramChangeRecord) doRecord;
					Function func = (Function) pcr.getObject();
					if (isFunctionSignatureChange(pcr)) {
						functionSignatureChanged(func.getEntryPoint());
					}
					else if (isFunctionModifierChange(pcr)) {
						functionModifierChanged(func.getEntryPoint());
					}
					break;
				case ChangeManager.DOCR_FUNCTION_ADDED:
				case ChangeManager.DOCR_FUNCTION_BODY_CHANGED:
					pcr = (ProgramChangeRecord) doRecord;
					func = (Function) pcr.getObject();
					if (!func.isExternal()) {
						functionDefined(func.getEntryPoint());
					}
					break;
				case ChangeManager.DOCR_FUNCTION_REMOVED:
					pcr = (ProgramChangeRecord) doRecord;
					Address oldEntry = pcr.getStart();
					functionTasks.notifyRemoved(oldEntry);
					break;
				case ChangeManager.DOCR_FALLTHROUGH_CHANGED:
				case ChangeManager.DOCR_FLOWOVERRIDE_CHANGED:
					// TODO: not sure if this should be done this way or explicitly
					// via the application commands (this is inconsistent with other
					// codeDefined cases which do not rely on change events (e.g., disassembly)
					pcr = (ProgramChangeRecord) doRecord;
					codeDefined(new AddressSet(pcr.getStart()));
					break;
// FIXME: must resolve cyclic issues before this can be done
//				case ChangeManager.DOCR_MEM_REFERENCE_ADDED:
//					// Allow high-priority reference-driven code analyzers a 
//					// shot at processing computed flows determined during 
//					// constant propagation.
//					pcr = (ProgramChangeRecord) doRecord;
//					Reference ref = (Reference) pcr.getNewValue();
//					RefType refType = ref.getReferenceType();
//					if (refType.isComputed()) {
//						codeDefined(ref.getFromAddress());
//					}
//					break;
				case ChangeManager.DOCR_CODE_ADDED:
					pcr = (ProgramChangeRecord) doRecord;
					if (pcr.getNewValue() instanceof Data) {
						AddressSet addressSet = new AddressSet(pcr.getStart(), pcr.getEnd());
						dataDefined(addressSet);
					}
					break;
			}
		}
	}

	/**
	 * Yield to all queued auto-analysis tasks of a higher priority (i.e., priority value less than the
	 * current analysis task priority value).  Must be careful to avoid recursive
	 * analysis scenarios which could cause stack overflows.   A limitPriority value of null is treated
	 * as special (used by GhidraScript worker) and will yield to all pending analysis.
	 * NOTE: method may only be invoked within the analysis thread
	 * (i.e., by an Analyzer or AnalysisWorker).  Care must be taken to control depth
	 * of yield, although this may be difficult to control.
	 * @param monitor the monitor
	 */
	private void yield(Integer limitPriority, TaskMonitor monitor) {

		if (limitPriority != null && limitPriority == 0) {
			// Handle special priority value 0 special and yield
			// to all pending analysis - this is the case for
			// scripts running within the analysis thread
			limitPriority = Integer.MAX_VALUE;
		}

		boolean originalIgnoreChanges = setIgnoreChanges(false);
		try {
			startAnalysis(monitor, true, limitPriority, false);
		}
		finally {
			setIgnoreChanges(originalIgnoreChanges);
		}
	}

	/**
	 * Allows all queued auto-analysis tasks with a priory value less than the specified
	 * limitPriority (lower values are considered to be a higher-priority) to complete.
	 * Any previously yielded tasks will remain in a yielded state.
	 * NOTE: This method should generally only be used by GhidraScripts.  Using this method
	 * is not recommended for Analyzers or their subordinate threads.  Invoking this method
	 * from a Analyzer subordinate thread will likely produce a deadlock situation.
	 * @param limitPriority property limit threshold - all tasks with a lower priority value
	 * (i.e., lower values correspond to higher priority) will be permitted to run.  A value
	 * of null will allow all pending analysis to complete (excluding any tasks which had
	 * previously yielded).
	 * @param monitor the monitor
	 * @throws IllegalStateException if not invoked from the analysis thread.
	 */
	public void waitForAnalysis(final Integer limitPriority, TaskMonitor monitor) {

		if (Thread.currentThread() != analysisThread) {

			if (SystemUtilities.isInHeadlessMode()) {
				if (analysisThread != null) {
					throw new IllegalStateException();
				}
				// assume synchronous environment - scripts and analysis use main thread
				startAnalysis(monitor, false, limitPriority, true);
				return;
			}

			program.flushPrivateEventQueue(eventQueueID);

			synchronized (this) {
				if (analysisThread == null && queue.isEmpty()) {
					return; // nothing new scheduled and analysis not active
				}
			}

			// Schedule analysis worker to block current-thread while we wait for analysis
			// to complete on analysis-thread
			try {
				scheduleWorker(new AnalysisWorker() {

					@Override
					public boolean analysisWorkerCallback(Program p, Object workerContext,
							TaskMonitor workerMonitor) throws Exception, CancelledException {
						AutoAnalysisManager.this.waitForAnalysis(limitPriority, workerMonitor);
						return true;
					}

					@Override
					public String getWorkerName() {
						return "Wait for Analysis";
					}
				}, null, true, monitor);
			}
			catch (CancelledException e) {
				// ignore
			}
			catch (InvocationTargetException e) {
				Msg.error(this, "Error occurred while waiting for analysis", e);
			}
			catch (InterruptedException e) {
				// ignore
			}
			return;
		}
		if (activeTask == null) {
			throw new AssertException();
		}

		// temporarily alter active task priority during yield processing
		Integer originalPriority = activeTask.taskPriority;
		activeTask.taskPriority = limitPriority;
		try {
			yield(limitPriority, monitor);
		}
		finally {
			activeTask.taskPriority = originalPriority;
		}
	}

	/**
	 * Alter the current program change listener state for this auto-analysis manager.
	 * NOTE: method only has an affect only when invoked within the analysis thread
	 * (i.e., by an Analyzer or AnalysisWorker)
	 * @param state if true subsequent program changes will not trigger auto-analysis, if
	 * false program changes could trigger auto-analysis on those changes
	 * @return previous state
	 */
	public boolean setIgnoreChanges(boolean state) {
		if (analysisThread != Thread.currentThread()) {
			Msg.warn(this, "AutoAnalysisManager.setIgnoreChanges had no affect " +
				"since it was not invoked within the analysis thread");
			return ignoreChanges;
		}
		return doSetIgnoreChanges(state);
	}

	/**
	 * Alter the current program change listener state for this auto-analysis manager.
	 * Bypasses thread safety check for controlled worker execution.
	 * @param state if true subsequent program changes will not trigger auto-analysis, if
	 * false program changes could trigger auto-analysis on those changes
	 * @return previous state
	 */
	private boolean doSetIgnoreChanges(boolean state) {
		if (ignoreChanges == state) {
			return state;
		}
		program.flushPrivateEventQueue(eventQueueID);
		ignoreChanges = state;
		return !state;
	}

	/**
	 * Start auto-analysis in the current thread if it is ENABLED and not yet running.
	 * WARNING! If auto analysis is actively running or is DISABLED/SUSPENDED, this method will return immediately.
	 * NOTE: If invoked directly or indirectly by an Analyzer a yield will be
	 * performed in which all queued tasks of a higher priority (smaller priority value) than the current
	 * task will be executed prior to this method returning.  AnalysisWorker's should use the
	 * yield method so that their limit-priority may be established during the yield.
	 * <br>
	 * If analysis is performed, a summary of task execution times will be printed to the log.
	 * @param monitor the monitor
	 */
	public void startAnalysis(TaskMonitor monitor) {
		startAnalysis(monitor, true);
	}

	// TODO: We need to make these startAnalysis methods work consistently for all situations
	// - i.e., should they always block until analysis is complete?

	/**
	 * Start auto-analysis in the current thread if it is ENABLED and not yet running.
	 * WARNING! If auto analysis is actively running or is DISABLED/SUSPENDED, this method will return immediately.
	 * NOTE: If invoked directly or indirectly by an Analyzer a yield will be
	 * performed in which all queued tasks of a higher priority (smaller priority value) than the current
	 * task will be executed prior to this method returning.  AnalysisWorker's should use the
	 * yield method so that their limit-priority may be established during the yield.
	 * @param monitor the monitor
	 * @param printTaskTimes if true and analysis is performed, a summary of task execution times
	 * will be printed to the log.
	 */
	public void startAnalysis(TaskMonitor monitor, boolean printTaskTimes) {
		if (Thread.currentThread() == analysisThread) {
			// TODO: should this yield for analysis?
			//    Thinking was that if some analysis causes disassembly to occur,
			//    then that disassembly and it's analysis will keep other analysis out of trouble.
			//    However for single threaded, this might not be worthwhile in the long run.
			yield(activeTask.taskPriority, monitor);
		}
		else if (analysisThread != null || !isEnabled) {
			// this could be a sub-thread of a task, don't yield, or flush domain objects
			return;
		}
		else {
			PluginTool tool = getAnalysisTool();
			if (tool != null && !tool.threadIsBackgroundTaskThread()) {
				startBackgroundAnalysis();
			}
			else {
				startAnalysis(monitor, false, null, printTaskTimes);
			}
		}
	}

	private class AnalysisTaskWrapper {

		private final BackgroundCommand task;
		Integer taskPriority;

		private long timeAccumulator;
		private long startTime;

		AnalysisTaskWrapper(BackgroundCommand task, int taskPriority) {
			this.task = task;
			this.taskPriority = taskPriority;
		}

		void run(Program p, TaskMonitor monitor) {
			startTime = System.currentTimeMillis();
			try {
				task.applyTo(p, monitor);
			}
			catch (RuntimeException th) {
				if (debugOn) {
					throw th;
				}
				if (!p.isClosed() && !p.hasTerminatedTransaction()) {
					String msg = th.getMessage();
					if (msg == null) {
						msg = "";
					}
					Msg.showError(this, null, "Analyzer Error",
						"Analysis Task: " + task.getName() + " - " + msg, th);
				}
			}
			long timeDiff = timeAccumulator + (System.currentTimeMillis() - startTime);
			totalTaskTime += timeDiff;
			addToTaskTime(task.getName(), timeDiff);
			startTime = 0;
			timeAccumulator = 0;

			p.flushPrivateEventQueue(eventQueueID);
		}

		void pauseTimer() {
			timeAccumulator += (System.currentTimeMillis() - startTime);
			startTime = 0;
		}

		void resumeTimer() {
			startTime = System.currentTimeMillis();
		}

	}

	/**
	 * Start auto-analysis if it is ENABLED and not yet running.
	 * @param monitor the monitor
	 * @param yield if true the current thread is the analysis thread and is yielding to the currently
	 * executing task.
	 * @param limitPriority the threshold priority value.  All queued tasks with a priority value
	 * less than limitPriority (i.e., higher priority) will be executed prior to this method returning.
	 * A null value should be specified to force all tasks to be executed.
	 * @param printTaskTimes if true and analysis is performed, a summary of task execution times
	 * will be printed to the log.
	 */
	private void startAnalysis(TaskMonitor monitor, boolean yield, Integer limitPriority,
			boolean printTaskTimes) {

		// the program may have been closed before while this thread was waiting
		if (program == null || program.isClosed()) {
			return;
		}

		program.flushPrivateEventQueue(eventQueueID);

		synchronized (this) {
			try {
				/**
				 * If invoked from an analysis task, treat as a yield and allow
				 * task queue to be processed.
				 */
				if (!yield && (!isEnabled || analysisThread != null)) {
					return;
				}
				if (yield) {
					if (activeTask == null) {
						throw new AssertException("Expected active analysis task");
					}
				}
				AnalysisTaskWrapper task = getNextTask(limitPriority, monitor);
				if (task == null) {
					return;
				}
				if (analysisThread == null) {
					analysisThread = Thread.currentThread();
				}
				if (yield) {
					activeTask.pauseTimer();
					yieldedTasks.push(activeTask);
				}
				activeTask = task;
			}
			finally {
				backgroundAnalysisPending = false;
			}
		}

		try {
			if (printTaskTimes) {
				clearTimedTasks();
			}
			while (true) {
				Program p = program; // program may get cleared by domain object change event
				if (p == null || p.hasTerminatedTransaction()) {
					monitor.cancel();
					cancelQueuedTasks();
					break;
				}

				activeTask.run(p, monitor);

				synchronized (this) {
					activeTask = getNextTask(limitPriority, monitor);
					if (activeTask == null) {
						if (!yield) {
							analysisThread = null;
						}
						break;
					}
				}
			}

			if (!yield) {
				notifyAnalysisEnded();
				if (printTaskTimes) {
					printTimedTasks();
					saveTaskTimes();
				}
			}
		}
		finally {
			synchronized (this) {
				if (yield) {
					activeTask = yieldedTasks.pop();
					activeTask.resumeTimer();
				}
				else {
					analysisTool = null;
					analysisThread = null;
					activeTask = null;
					protectedLocations = new AddressSet();
					yieldedTasks.clear();
				}
			}
		}
	}

	private AnalysisTaskWrapper getNextTask(Integer limitPriority, TaskMonitor monitor) {
		if (monitor.isCancelled()) {
			cancelQueuedTasks();
		}

		if (!isEnabled || queue.isEmpty() ||
			(limitPriority != null && queue.getFirstPriority() >= limitPriority)) {
			return null;
		}
		int nextTaskPriority = queue.getFirstPriority();
		return new AnalysisTaskWrapper(queue.removeFirst(), nextTaskPriority);
	}

	public void addListener(AutoAnalysisManagerListener listener) {
		if (!listeners.contains(listener)) {
			listeners.add(listener);
		}
	}

	public void removeListener(AutoAnalysisManagerListener listener) {
		listeners.remove(listener);
	}

	private void notifyAnalysisEnded() {
		for (AnalysisTaskList list : taskArray) {
			list.notifyAnalysisEnded(program);
		}
		for (AutoAnalysisManagerListener listener : listeners) {
			listener.analysisEnded(this);
		}
		log.clear();
	}

	/**
	 * Returns true if the analyzer is still executing.
	 * @return true if the analyzer is still executing
	 */
	public synchronized boolean isAnalyzing() {
		if ((program == null) || program.isClosed()) {
			return false;
		}
		return analysisThread != null || backgroundAnalysisPending;
	}

	/**
	 * Tell all the tasks that they are canceled.
	 */
	public synchronized void cancelQueuedTasks() {
		while (!queue.isEmpty()) {
			BackgroundCommand cmd = queue.getFirst();
			if (cmd instanceof AnalysisWorkerCommand) {
				AnalysisWorkerCommand workerCmd = (AnalysisWorkerCommand) cmd;
				if (!workerCmd.canCancel()) {
					return;
				}
			}
			cmd = queue.removeFirst();
			cmd.dispose();
		}
	}

	synchronized boolean schedule(BackgroundCommand cmd, int priority) {

		if (cmd == null) {
			throw new IllegalArgumentException("Can't schedule a null command");
		}
		queue.add(cmd, priority);

		return startBackgroundAnalysis();
	}

	/**
	 * Start auto-analysis in background (only supported in tool environment when
	 * AutoAnalysisManagerPlugin installed)
	 * @return true if successfully scheduled background task or auto-analysis is already
	 * scheduled/running.
	 */
	public synchronized boolean startBackgroundAnalysis() {

		if (!isEnabled) {
			return false;
		}
		if (analysisThread != null || backgroundAnalysisPending) {
			return true;
		}

		analysisTool = getActiveTool(program);
		if (analysisTool != null) {
			AnalysisBackgroundCommand analysisCmd = new AnalysisBackgroundCommand(this, false);
			backgroundAnalysisPending = true;
			analysisTool.scheduleFollowOnCommand(analysisCmd, program);
			return true;
		}
		return false;
	}

	public DataTypeManagerService getDataTypeManagerService() {
		PluginTool tool = getActiveTool(program);
		DataTypeManagerService dtmService = null;
		if (tool != null) {
			dtmService = tool.getService(DataTypeManagerService.class);
		}

		if (dtmService != null) {
			return dtmService;
		}

		if (service == null) {
// TODO: instantiate with program so it can have access to programs DTM

			// Note: there is no tool in headless mode
			service = new DefaultDataTypeManagerService();
		}
		return service;
	}

	/**
	 * Returns the tool being used for analysis.  <b>This can be null</b> if analysis has never
	 * been run or if the tool that previously ran analysis has been closed.
	 * @return the tool being used for analysis.
	 */
	public synchronized PluginTool getAnalysisTool() {
		if (analysisTool == null) {
			analysisTool = getActiveTool(program);
		}
		return analysisTool;
	}

	private static PluginTool getActiveTool(Program program) {
		WeakSet<PluginTool> toolSet = toolMap.get(program);
		if (toolSet.isEmpty()) {
			return null;
		}

		PluginTool anyTool = null;
		Iterator<PluginTool> iterator = toolSet.iterator();
		while (iterator.hasNext()) {
			PluginTool tool = iterator.next();

			anyTool = tool;
			JFrame toolFrame = tool.getToolFrame();
			if (toolFrame != null && toolFrame.isActive()) {
				return tool;
			}
		}

		return anyTool;
	}

	public static synchronized boolean hasAutoAnalysisManager(Program program) {
		return managerMap.containsKey(program);
	}

	public static synchronized AutoAnalysisManager getAnalysisManager(Program program) {

		AutoAnalysisManager mgr = managerMap.get(program);
		if (mgr == null) {
			mgr = new AutoAnalysisManager(program);
			managerMap.put(program, mgr);
		}
		return mgr;
	}

	public void dispose() {
		doDispose(program);
		program = null;
	}

	/* This method takes the program param in case multiple threads are calling dispose at once */
	private void doDispose(Program localProgram) {
		if (localProgram == null) {
			return; // already been disposed()
		}

		localProgram.removeListener(this);

		synchronized (this) { // sync against multiple dispose calls
			if (service != null) {
				service.dispose();
				service = null;
			}
		}

		managerMap.remove(localProgram);
		toolMap.remove(localProgram);

		synchronized (this) {
			queue.clear();
			for (AnalysisTaskList list : taskArray) {
				list.clear();
			}
		}

		localProgram.removePrivateEventQueue(eventQueueID);
	}

	public void addTool(PluginTool tool) {
		WeakSet<PluginTool> toolSet = toolMap.get(program);
		toolSet.add(tool);
		initializeToolOptions(tool);
	}

	public void removeTool(PluginTool tool) {
		WeakSet<PluginTool> toolSet = toolMap.get(program);
		toolSet.remove(tool);
		if (analysisTool == tool) {
			analysisTool = null;
		}
	}

	private void initializeToolOptions(PluginTool tool) {
		Options options = tool.getOptions("Auto Analysis");
		options.registerOption(OPTION_NAME_THREAD_USE, analysisSharedThreadPoolSize, null,
			OPTION_DESCRIPTION_THREAD_USE);
		analysisSharedThreadPoolSize = getSharedThreadPoolSizeOption(tool);
	}

	private static int getSharedThreadPoolSizeOption(PluginTool tool) {
		Options options = tool.getOptions("Auto Analysis");
		return options.getInt(OPTION_NAME_THREAD_USE, analysisSharedThreadPoolSize);
	}

	public void registerOptions() {
		Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
		registerOptions(options);
	}

	public void initializeOptions() {
		Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);

		try {
			initializeOptions(options);
		}
		catch (OptionsVetoException e) {
// FIXME!! Not good to popup for all use cases
			// This will only happen if an Analyzer author makes a mistake 
			Msg.showError(this, null, "Invalid Analysis Option",
				"Invalid Analysis option set during initialization", e);
		}
	}

	public void initializeOptions(Options options) {
		byteTasks.optionsChanged(options);
		functionTasks.optionsChanged(options);
		functionModifierChangedTasks.optionsChanged(options);
		functionSignatureChangedTasks.optionsChanged(options);
		instructionTasks.optionsChanged(options);
		dataTasks.optionsChanged(options);
	}

	public void registerOptions(Options options) {
		byteTasks.registerOptions(options);
		functionTasks.registerOptions(options);
		functionModifierChangedTasks.registerOptions(options);
		functionSignatureChangedTasks.registerOptions(options);
		instructionTasks.registerOptions(options);
		dataTasks.registerOptions(options);
	}

	public void restoreDefaultOptions() {
		boolean commit = false;
		int id = program.startTransaction("Restore Default Analysis Options");
		try {
			Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
			for (String propertyName : options.getOptionNames()) {
				options.restoreDefaultValue(propertyName);
			}

			commit = true;
		}
		finally {
			program.endTransaction(id, commit);
		}
	}

	boolean askToAnalyze(PluginTool tool) {
		if (program == null) {
			return false;
		}
		//if program has just been instantiated, then we can analyze it.
		if (!program.canSave() && !program.isChanged()) {
			return false;
		}
		if (GhidraProgramUtilities.shouldAskToAnalyze(program)) {
			int answer = OptionDialog.showYesNoDialog(tool.getToolFrame(), "Analyze",
				"<html>" + HTMLUtilities.escapeHTML(program.getDomainFile().getName()) +
					" has not been analyzed. Would you like to analyze it now?");
			//Set to false for now.  ANALYZED is a tri-valued variable:
			// null means not asked.
			// false means asked but could still turn true when analysis happens.
			// true means analysis has started.
			//Setting false here only works due to this code only being reachable
			// because of the behavior of GhidraProgramUtilities.shouldAskToAnalyze(program) above.
			GhidraProgramUtilities.setAnalyzedFlag(program, false);
			return answer == OptionDialog.OPTION_ONE; //Analyze
		}
		return false;
	}

	private synchronized int getDisassemblyPriority() {
		// get a priority of 1 less than the current running task (a higher priority),
		//   or a normal disassembly priority if no task is running.
		if (activeTask == null || activeTask.taskPriority == null) {
			return AnalysisPriority.DISASSEMBLY.priority();
		}
		return activeTask.taskPriority - 2;
	}

	private int getFunctionPriority() {
		// should be 1 higher, so disassembly happens first
		return getDisassemblyPriority() + 1;
	}

	public void disassemble(Address target) {
		schedule(new DisassembleCommand(target, null, true), getDisassemblyPriority());
	}

	public void createFunction(Address target, boolean findFunctionStart) {
		schedule(new CreateFunctionCmd(target, findFunctionStart), getFunctionPriority());
	}

	public void disassemble(AddressSetView targetSet) {
		schedule(new DisassembleCommand(targetSet, null, true), getDisassemblyPriority());
	}

	public void createFunction(AddressSetView targetSet, boolean findFunctionStarts) {
		schedule(new CreateFunctionCmd(targetSet, findFunctionStarts), getFunctionPriority());
	}

	public void disassemble(AddressSetView targetSet, AnalysisPriority priority) {
		schedule(new DisassembleCommand(targetSet, null, true), priority.priority());
	}

	public void createFunction(AddressSetView targetSet, boolean findFunctionStarts,
			AnalysisPriority priority) {
		schedule(new CreateFunctionCmd(targetSet, findFunctionStarts), priority.priority());
	}

	/**
	 * Get the set of addresses that have been protected from clearing
	 * 
	 * @return protected locations
	 */
	public AddressSetView getProtectedLocations() {
		return new AddressSetViewAdapter(protectedLocations);
	}

	/**
	 * Add a location that is know good code to be protected from clearing for this Analysis run only.
	 * 
	 * @param addr address to protect
	 */
	public void setProtectedLocation(Address addr) {
		protectedLocations.add(addr);
	}

	/**
	 * Add a set of known good code locations to be protected from clearing for this Analysis run only.
	 * 
	 * @param set of addresses to protect
	 */
	public void setProtectedLocations(AddressSet set) {
		protectedLocations.add(set);
	}

	/**
	 * Get the names of the tasks that have run
	 *
	 * @return an array of task names
	 */
	public String[] getTimedTasks() {
		String values[] = new String[timedTasks.size()];
		List<String> list = new ArrayList<>();
		list.addAll(timedTasks.keySet());
		Collections.sort(list);
		return list.toArray(values);
	}

	/**
	 * Get the time taken by a named task
	 * The names of tasks that have run can be retrieved using getTimedTasks
	 * @param map the times by task names
	 * @param taskName the task name
	 * @return the time taken by a named task
	 */
	public long getTaskTime(Map<String, Long> map, String taskName) {
		Long time = map.get(taskName);
		if (time == null) {
			return -1;
		}
		return time.longValue();
	}

	/**
	 * Get rid of timed tasks that have run
	 *
	 */
	private void clearTimedTasks() {
		timedTasks.clear();
		totalTaskTime = 0;
	}

	private long getUpdatedTaskTime(Map<String, Long> map, String taskName, long newTime) {
		long totalTime = newTime;
		long currentTime = getTaskTime(map, taskName);
		if (currentTime > 0) {
			totalTime += currentTime;
		}
		return totalTime;
	}

	private void addToTaskTime(String taskName, long time) {
		long l = getUpdatedTaskTime(timedTasks, taskName, time);
		timedTasks.put(taskName, l);

		l = getUpdatedTaskTime(cumulativeTasks, taskName, time);
		cumulativeTasks.put(taskName, l);
	}

	/**
	 * Get the total time of the last autoAnalysis run
	 *
	 * @return time in milliseconds of last run
	 */
	public int getTotalTimeInMillis() {
		return totalTaskTime;
	}

	/**
	 * Get a summary of the time for each task that ran for this auto analysis run
	 * @return the string summary
	 */
	public String getTaskTimesString() {

		StringBuffer taskTimesStringBuf = new StringBuffer();

		String spacer = "                                                     ";

		taskTimesStringBuf.append("-----------------------------------------------------\n");

		String taskNames[] = getTimedTasks();
		for (String element : taskNames) {
			long taskTime = getTaskTime(timedTasks, element);
			double totalTime = taskTime / 1000.00;

			String partTime = (((int) (totalTime * 1000.0)) % 1000) + "";
			String secString =
				((int) totalTime) + "." + "000".substring(partTime.length()) + partTime + " secs";
			int testLen = element.length() + secString.length();
			if (testLen > spacer.length()) {
				testLen = spacer.length() - 5;
			}
			taskTimesStringBuf.append(
				"    " + element + spacer.substring(testLen) + secString + "\n");
		}

		taskTimesStringBuf.append("-----------------------------------------------------\n");
		taskTimesStringBuf.append(
			"     Total Time   " + (int) (totalTaskTime / 1000.00) + " secs\n");
		taskTimesStringBuf.append("-----------------------------------------------------\n");

		return taskTimesStringBuf.toString();
	}

	private void printTimedTasks() {
		if (totalTaskTime < 1000) {
			return;
		}

		String taskTimeString = getTaskTimesString();
		Msg.info(this, taskTimeString);
	}

	private void saveTaskTimes() {

		StoredAnalyzerTimes times = StoredAnalyzerTimes.getStoredAnalyzerTimes(program);

		String taskNames[] = getTimedTasks();
		for (String element : taskNames) {
			long taskTimeMSec = getTaskTime(timedTasks, element);
			times.addTime(element, taskTimeMSec);
		}

		StoredAnalyzerTimes.setStoredAnalyzerTimes(program, times);
	}

	/**
	 * Schedule an analysis worker to run while auto analysis is suspended.  Invocation will block
	 * until callback is completed or cancelled.  If an analysis task is busy, it will be allowed to
	 * complete before the worker callback occurs.  This method will cause the AnalysisWorker to
	 * run at the highest priority (reserved priority value of 0).  Within headed environments when analyzeChanges
	 * is false, a modal task dialog will be displayed while the callback is active to prevent the
	 * user from initiating additional program changes.  If this worker invokes startAnalysis, it will
	 * yield to ALL pending analysis.
	 * <p>Known Limitations:
	 * <ul>
	 * <li>If ad-hoc background threads are making program changes, their associated
	 * program change events could be ignored by the AutoAnalysisManager</li>
	 * <li>In headless environments, or if the target program is not open within a tool which
	 * contains the AutoAnalysisPlugin, all invocations will perform the callback immediately
	 * without regard to other threads which may be changing the program</li>
	 * </ul>
	 * @param worker the worker instance to be invoked while analysis is inactive.
	 * @param workerContext any data required by the worker to complete its task or null if worker
	 * instance will retain the necessary state.
	 * @param analyzeChanges if false program changes which occur while the worker is running will not trigger
	 * follow-on analysis of those changes.  If false it is critical that the worker be associated with a modal
	 * task dialog which will prevent unrelated concurrent changes being made to the program while
	 * the worker is active.
	 * @param workerMonitor the worker's monitor
	 * @return boolean value returned by worker.analysisWorkerCallback
	 * @throws InvocationTargetException if worker throws exception while running (see cause)
	 * @throws InterruptedException if caller's thread is interrupted.  If this occurs a cancel
	 * condition will be forced on the workerMonitor so that the worker will stop running.
	 * @throws CancelledException if the job is cancelled
	 * @see AnalysisPriority for priority values
	 */
	public boolean scheduleWorker(AnalysisWorker worker, Object workerContext,
			boolean analyzeChanges, final TaskMonitor workerMonitor)
			throws InvocationTargetException, InterruptedException, CancelledException {

		if (!SystemUtilities.isInHeadlessMode() && SwingUtilities.isEventDispatchThread()) {
			throw new UnsupportedOperationException(
				"AutoAnalysisManager.scheduleWorker may not be invoked from Swing thread");
		}
		workerMonitor.checkCanceled();

		AnalysisWorkerCommand cmd =
			new AnalysisWorkerCommand(worker, workerContext, analyzeChanges, workerMonitor);
		workerMonitor.checkCanceled();

		// NOTE: It is very important that the worker cmd not run concurrent with analysis
		if (SystemUtilities.isInHeadlessMode()) {
			// do immediately if running headless
			cmd.applyToWithTransaction(program, workerMonitor);
		}
		else if (isAnalysisToolBackgroundThread() || getAnalysisTool() == null) {
			// do immediately if running within the analysis thread group or no analysis tool exists
			cmd.applyToWithTransaction(program, workerMonitor);
		}
		else {
			synchronized (cmd) {
				workerMonitor.setMessage("Waiting for auto-analysis...");
				Msg.debug(this, "Scheduling analysis worker (" + cmd.worker.getWorkerName() +
					"): " + cmd.worker.getClass());
				schedule(cmd, 0);
				try {
					cmd.wait(); // wait for AnalysisWorkerCommand to complete
				}
				catch (InterruptedException e) {
					if (workerMonitor.isCancelEnabled()) {
						workerMonitor.cancel();
					}
					throw e;
				}
			}
		}

		workerMonitor.checkCanceled();
		Msg.debug(this, "Analysis worker completed (" + cmd.worker.getWorkerName() + "): " +
			cmd.worker.getClass());

		InvocationTargetException workerException = cmd.getWorkerException();
		if (workerException != null) {
			throw workerException;
		}
		return cmd.getReturn();
	}

	private synchronized boolean isAnalysisToolBackgroundThread() {
		PluginTool tool = getAnalysisTool();
		if (tool == null) {
			return false;
		}
		return tool.threadIsBackgroundTaskThread();
	}

	private static String fixupTitle(String title) {
		if (title != null) {
			return title;
		}
		return "Analyzing...";
	}

//==================================================================================================
// Thread Pool Methods
//==================================================================================================

//==================================================================================================

	/**
	 * Returns a thread pool that is meant to be shared amongst Analyzers that wish to run
	 * in parallel.  Normally, this will only be used by one analyzer at a time.   However, if
	 * multiple tools are running, then they will share this pool.
	 *
	 * @return the shared analysis thread pool
	 */
	public static GThreadPool getSharedAnalsysThreadPool() {
		GThreadPool pool = GThreadPool.getSharedThreadPool(SHARED_THREAD_POOL_NAME);

		updateSharedThreadPoolSize();
		pool.setMaxThreadCount(analysisSharedThreadPoolSize);
		return pool;
	}

	private static void updateSharedThreadPoolSize() {
		PluginTool tool = getAnyTool();
		if (tool == null) {
			return;
		}

		int currentToolSize = getSharedThreadPoolSizeOption(tool);
		if (toolCount() == 1) {
			// only one tool, just use its value
			analysisSharedThreadPoolSize = currentToolSize;
		}
		else {
			// many tools, just keep the largest value
			analysisSharedThreadPoolSize = Math.max(analysisSharedThreadPoolSize, currentToolSize);
		}
	}

	private static PluginTool getAnyTool() {
		PluginTool anyTool = null;
		Collection<WeakSet<PluginTool>> values = toolMap.values();
		for (WeakSet<PluginTool> weakSet : values) {
			for (PluginTool tool : weakSet) {
				JFrame toolFrame = tool.getToolFrame();
				if (toolFrame != null && toolFrame.isActive()) {
					return tool;
				}
			}
		}
		return anyTool;
	}

	private static int toolCount() {
		int n = 0;
		Collection<WeakSet<PluginTool>> values = toolMap.values();
		for (WeakSet<PluginTool> weakSet : values) {
			n += weakSet.size();
		}
		return n;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class JointTaskMonitor implements TaskMonitor {

		private TaskMonitor primaryMonitor;
		private TaskMonitor secondaryMonitor;

		JointTaskMonitor(TaskMonitor primaryMonitor, TaskMonitor secondaryMonitor) {
			this.primaryMonitor = primaryMonitor;
			this.secondaryMonitor = secondaryMonitor;
		}

		@Override
		public boolean isCancelled() {
			return primaryMonitor.isCancelled() || secondaryMonitor.isCancelled();
		}

		@Override
		public void setShowProgressValue(boolean showProgressValue) {
			// ignore
		}

		@Override
		public void setIndeterminate(boolean indeterminate) {
			// ignore
		}

		@Override
		public boolean isIndeterminate() {
			return false;
		}

		@Override
		public void setMessage(String message) {
			primaryMonitor.setMessage(message);
			secondaryMonitor.setMessage(message);
		}

		@Override
		public String getMessage() {
			return primaryMonitor.getMessage();
		}

		@Override
		public void setProgress(long value) {
			primaryMonitor.setProgress(value);
			secondaryMonitor.setProgress(value);
		}

		@Override
		public void initialize(long max) {
			primaryMonitor.initialize(max);
			secondaryMonitor.initialize(max);
		}

		@Override
		public void setMaximum(long max) {
			primaryMonitor.setMaximum(max);
			secondaryMonitor.setMaximum(max);
		}

		@Override
		public long getMaximum() {
			return Math.max(primaryMonitor.getMaximum(), secondaryMonitor.getMaximum());
		}

		@Override
		public void checkCanceled() throws CancelledException {
			primaryMonitor.checkCanceled();
			secondaryMonitor.checkCanceled();
		}

		@Override
		public void incrementProgress(long incrementAmount) {
			primaryMonitor.incrementProgress(incrementAmount);
			secondaryMonitor.incrementProgress(incrementAmount);
		}

		@Override
		public long getProgress() {
			return Math.max(primaryMonitor.getProgress(), secondaryMonitor.getProgress());
		}

		@Override
		public void cancel() {
			primaryMonitor.cancel();
			secondaryMonitor.cancel();
		}

		@Override
		public void addCancelledListener(CancelledListener listener) {
			primaryMonitor.addCancelledListener(listener);
		}

		@Override
		public void removeCancelledListener(CancelledListener listener) {
			primaryMonitor.addCancelledListener(listener);
		}

		@Override
		public void setCancelEnabled(boolean enable) {
			primaryMonitor.setCancelEnabled(enable);
			secondaryMonitor.setCancelEnabled(enable);
		}

		@Override
		public boolean isCancelEnabled() {
			return primaryMonitor.isCancelEnabled();
		}

		@Override
		public void clearCanceled() {
			primaryMonitor.clearCanceled();
			secondaryMonitor.clearCanceled();
		}
	}

	/**
	 * <code>AnalysisWorkerCommand</code> facilitates the controlled callback to an AnalysisWorker.
	 * In a Headed environment a modal task dialog will be used to block user input if the
	 * worker was scheduled with analyzeChanges==false
	 */
	private class AnalysisWorkerCommand extends BackgroundCommand implements CancelledListener {

		private AnalysisWorker worker;
		private Object workerContext;
		private boolean analyzeChanges;
		private TaskMonitor workerMonitor;

		private boolean commandKilled;
		private boolean returnValue;
		private InvocationTargetException exception;

		AnalysisWorkerCommand(AnalysisWorker worker, Object workerContext, boolean analyzeChanges,
				TaskMonitor workerMonitor) {
			super(worker.getWorkerName(), false, workerMonitor.isCancelEnabled(), false);
			this.worker = worker;
			this.workerContext = workerContext;
			this.analyzeChanges = analyzeChanges;
			this.workerMonitor = workerMonitor;
			workerMonitor.addCancelledListener(this);
		}

		InvocationTargetException getWorkerException() {
			return exception;
		}

		boolean getReturn() {
			return returnValue;
		}

		@Override
		public synchronized void cancelled() {
			// Initial state: while this command is queued we must listen to the worker's task monitor
			// so that we can kill ourself
			// Running state: while the command is running we are listening to the analysis task
			// monitor and must convey it being cancelled to the worker's monitor.
			if (workerMonitor.isCancelEnabled()) {
				doNotRun();
			}
		}

		private void doNotRun() {
			// We can only cancel if worker monitor allows it
			commandKilled = true;
			exception = new InvocationTargetException(new CancelledException());
			workerMonitor.cancel();
			synchronized (this) {
				notifyAll(); // Allow waiting scheduleWorker method to return
			}
		}

		@Override
		public void dispose() {
			// Cancelled prior to execution
			doNotRun();
			super.dispose();
		}

		boolean applyToWithTransaction(Program p, TaskMonitor analysisMonitor) {
			int txId = p.startTransaction(worker.getWorkerName());
			try {
				return applyTo(p, analysisMonitor);
			}
			finally {
				p.endTransaction(txId, true);
			}
		}

		@Override
		public boolean applyTo(DomainObject obj, TaskMonitor analysisMonitor) {

			synchronized (this) {
				workerMonitor.removeCancelledListener(this);
				if (commandKilled) {
					notifyAll(); // Allow waiting scheduleWorker method to return
					return false;
				}

				assert (obj == program);

				if (analysisMonitor != workerMonitor) {
					if (!workerMonitor.isCancelEnabled()) {
						analysisMonitor.setCancelEnabled(false);
					}
					analysisMonitor.addCancelledListener(this);
				}

				if (!analyzeChanges && ignoreChanges) {
					// we must be a nested worker where the outer worker
					// has requested us to ignore changes
					// set analyzeChanges to true to keep running
					// under current state
					analyzeChanges = true;
				}
			}

			WorkerBlockerTask blockerTask = null;
			boolean wasIgnoringChanges = ignoreChanges;
			try {
				if (!analyzeChanges && !SystemUtilities.isInHeadlessMode()) {
					blockerTask = new WorkerBlockerTask();
				}

				if (!analyzeChanges) {
					// analysis should ignore change events
					doSetIgnoreChanges(true);
				}

				Msg.debug(this, "Invoking analysis worker (" + worker.getWorkerName() + "): " +
					worker.getClass());

				JointTaskMonitor monitor = new JointTaskMonitor(workerMonitor, analysisMonitor);

				returnValue = worker.analysisWorkerCallback(program, workerContext, monitor);
			}
			catch (CancelledException e) {
				// ignore
			}
			catch (Throwable t) {
				exception = new InvocationTargetException(t);
			}
			finally {
				if (!analyzeChanges) {
					// restore event handling state if we had disabled it
					doSetIgnoreChanges(wasIgnoringChanges);
				}

				if (blockerTask != null) {
					blockerTask.terminate();
				}

				if (analysisMonitor != workerMonitor) {
					analysisMonitor.removeCancelledListener(this);
					analysisMonitor.setCancelEnabled(true);
					// prevent cancel from affecting other queued analysis
					analysisMonitor.clearCanceled();
				}

				synchronized (this) {
					notifyAll(); // Allow waiting scheduleWorker method to return
				}
			}

			return true;
		}

		/**
		 * <code>WorkerBlockerTask</code> provides the means to block user input via a
		 * modal dialog while an analysis worker has either disabled or suspended auto-analysis
		 * (i.e., ignoring change events).
		 */
		private class WorkerBlockerTask extends Task implements CancelledListener, Runnable {

			private CountDownLatch latch = new CountDownLatch(1);

			WorkerBlockerTask() {
				super(fixupTitle(worker.getWorkerName()), workerMonitor.isCancelEnabled(), false,
					true);
				Msg.trace(AutoAnalysisManager.this, "Constructor - starting thread...");
				Thread t = new Thread(this);
				t.start();
				Msg.trace(AutoAnalysisManager.this, "\tafter starting thread");
				try {
					// ensure that terminate can not be invoked
					// before run method has invoked wait
					Msg.trace(AutoAnalysisManager.this, "\tcalling latch.await()");
					latch.await();
					Msg.trace(AutoAnalysisManager.this, "\tafter await()");
				}
				catch (InterruptedException e) {
					// should not happen
					Msg.trace(AutoAnalysisManager.this, "await() interrupted!");
				}
			}

			@Override
			public void run() {
				Msg.trace(AutoAnalysisManager.this, "run()");
				new TaskLauncher(this, null, 0);
			}

			synchronized void terminate() {
				Msg.trace(AutoAnalysisManager.this, "terminate()");
				notifyAll(); // Allow waiting WorkerBlockerTask to complete
			}

			@Override
			public void run(TaskMonitor monitor) {
				Msg.trace(this, "run(TaskMonitor)");
				monitor.setMessage("Analyzing...");
				monitor.addCancelledListener(this);
				try {
					synchronized (this) {
						Msg.trace(AutoAnalysisManager.this, "\tlatch countDown()");
						latch.countDown();
						Msg.trace(AutoAnalysisManager.this, "\tcalling wait()");
						wait();
						Msg.trace(AutoAnalysisManager.this, "\tafter wait()");
					}
				}
				catch (InterruptedException e) {
					// should not happen
					Msg.trace(AutoAnalysisManager.this, "wait() interrupted!");
				}
				finally {
					Msg.trace(AutoAnalysisManager.this, "finally");
					monitor.removeCancelledListener(this);
				}
			}

			@Override
			public void cancelled() {
				Msg.trace(AutoAnalysisManager.this, "stateChanged(TaskMonitor)");
				if (workerMonitor.isCancelEnabled()) {
					Msg.trace(AutoAnalysisManager.this, "\tcalling cancel on worker monitor");
					workerMonitor.cancel();
				}
			}
		}
	}
}
