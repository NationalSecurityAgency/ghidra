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
import java.io.File;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.app.services.DebuggerModelService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.dbg.DebugModelConventions;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.target.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.trace.database.DBTrace;
import ghidra.trace.model.Trace;
import ghidra.trace.model.time.TraceTimeManager;
import ghidra.util.database.UndoableTransaction;

/**
 * This script populates a trace database for demonstrations purposes and opens it in the current
 * tool.
 * 
 * <p>
 * Your current tool had better be the "TraceBrowser"! The demonstration serves two purposes. 1) It
 * puts interesting data into the TraceBrowser and leaves some annotations as an exercise. 2) It
 * demonstrates how a decent portion the Trace API works.
 * 
 * <p>
 * A Trace is basically a collection of observations of memory and registers over the lifetime of an
 * application or computer system. In Ghidra, the Trace object also supports many of the same
 * annotations as does Program. In the same way that Program brings knowledge markup to an image of
 * bytes, Trace brings knowledge markup to bytes observed over time.
 * 
 * <p>
 * Effectively, if you take the cross-product of Program with time and add Threads, Breakpoints,
 * etc., you get Trace. It's a lot. In order to use all the UI components which take a Program,
 * Trace can present itself as a Program at a particular point in time.
 * 
 * <p>
 * Each particular component will be introduced as its used in the script below, but for now some
 * core concepts:
 * 
 * <ul>
 * <li>A point in time is called a "tick." These don't necessarily correspond to any real unit of
 * time, though they may. The only requirement is that they are numbered in chronological
 * order.</li>
 * <li>Every annotation has a "lifespan," which is the range of ticks for which the annotation is
 * effective. Some annotations may overlap, others may not. In general, if the corresponding concept
 * in Program permits address overlap, then Trace permits both address and time overlap. If not,
 * then neither is permitted. In essense, Trace defines overlap as the intersection of rectangles,
 * where an annotation's X dimension is it's address range, and its Y dimension is its lifespan.
 * </li>
 * <li>Observations in memory happen at a particular tick and are assumed in effect until another
 * observation changes that. To record the "freshness" of observations, the memory manager tags
 * regions as KNOWN, UNKNOWN, or ERROR. An observation implicitly marks the affected region as
 * KNOWN. The intent is to grey the background for regions where memory is UNKNOWN for the current
 * tick.</li>
 * <li>Observations of registers behave exactly the same as observations for memory, by leveraging
 * Ghidra's "register space." The only difference is that those observations must be recorded with
 * respect to a given thread. Each thread is effectively allocated its own copy of the register
 * space. Most the the API components require you to obtain a special "register space" for a given
 * thread before recording observations of or applying annotations to that thread.</li>
 * </ul>
 * 
 * <p>
 * After you've run this script, a trace should appear in the UI. Note that there is not yet a way
 * to save a trace in the UI. As an exercise, try adding data units to analyze the threads' stacks.
 * It may take some getting accustomed to, but the rules for laying down units should be very
 * similar to those in a Program. However, the Trace must take the applied units and decide how far
 * into the future they are effective. In general, it defaults to "from here on out." However, two
 * conditions may cause the trace to choose an ending tick: 1) The underlying bytes change sometime
 * in the future, and 2) There is an overlapping code unit sometime in the future.
 * 
 * <p>
 * The trace chooses the latest tick possible preceding any byte change or existing code unit, so
 * that the unit's underlying bytes remain constant for its lifespan, and the unit does not overlap
 * any existing unit. This rule causes some odd behavior for null-terminated strings. I intend to
 * adjust this rule slightly for static data types wrt/ byte changes. For those, the placed unit
 * should be truncated as described above, however, another data unit of the same type can be placed
 * at the change. The same rule is then applied iteratively into the future until an overlapping
 * unit is encountered, or there are no remaining byte changes.
 */
public class PopulateTraceRemote extends GhidraScript {

	private Language lang;
	private CompilerSpec cspec;
	private Trace trace;
	private TraceTimeManager timeManager;

	private AddressSpace defaultSpace;

	private DebuggerTraceManagerService manager;
	private DebuggerModelService targets;

	/**
	 * Create an address in the processor's (x86_64) default space.
	 * 
	 * @param offset the byte offset
	 * @return the address
	 */
	protected Address addr(long offset) {
		return defaultSpace.getAddress(offset);
	}

	/**
	 * Create an address range in the processor's default space.
	 * 
	 * @param min the minimum byte offset
	 * @param max the maximum (inclusive) byte offset
	 * @return the range
	 */
	protected AddressRange rng(long min, long max) {
		return new AddressRangeImpl(addr(min), addr(max));
	}

	/**
	 * Get a register by name
	 * 
	 * @param name the name
	 * @return the register
	 */
	protected Register reg(String name) {
		return lang.getRegister(name);
	}

	@Override
	protected void run() throws Exception {

		File f = askFile("Trace", "Load");

		cspec = currentProgram.getCompilerSpec();
		lang = currentProgram.getLanguage();
		defaultSpace = lang.getAddressFactory().getDefaultAddressSpace();
		trace = new DBTrace(f.getName(), cspec, this);

		PluginTool tool = state.getTool();
		manager = tool.getService(DebuggerTraceManagerService.class);
		targets = tool.getService(DebuggerModelService.class);

		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Populate Events", true)) {
			timeManager = trace.getTimeManager();
			timeManager.createSnapshot("init");
		}

		manager.openTrace(trace);
		manager.activateTrace(trace);

		Set<DebuggerObjectModel> models = targets.getModels();
		DebuggerObjectModel model = (DebuggerObjectModel) models.toArray()[0];
		TargetInterpreter interpreter =
			DebugModelConventions.findSuitable(TargetInterpreter.class, model.getModelRoot()).get();
		interpreter.execute(".opendump " + f.getAbsolutePath()).get();
		interpreter.execute("g");
		TargetAttacher attacher =
			DebugModelConventions.findSuitable(TargetAttacher.class, model.getModelRoot()).get();
		// TODO: Is "Available" the correct path?
		attacher.attach(model.getModelObject("Available", "[0]").as(TargetAttachable.class)).get();
	}
}
