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
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

import com.google.common.collect.Range;

import agent.dbgeng.dbgeng.DebugClient;
import agent.dbgeng.dbgeng.DebugControl;
import agent.dbgmodel.dbgmodel.DbgModel;
import agent.dbgmodel.dbgmodel.bridge.HostDataModelAccess;
import agent.dbgmodel.dbgmodel.main.ModelObject;
import agent.dbgmodel.impl.dbgmodel.bridge.HDMAUtil;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.trace.database.DBTrace;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.modules.TraceModuleManager;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.thread.TraceThreadManager;
import ghidra.trace.model.time.TraceTimeManager;
import ghidra.util.Msg;
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
public class PopulateTraceLocal extends GhidraScript {

	/**
	 * The Memory APIs all use Java NIO ByteBuffer. While it has it can sometimes be annoying, it
	 * provides most of the conveniences you'd need for packing arbitrary data into a memory buffer.
	 * I'll allocate one here large enough to write a couple values at a time.
	 */
	private ByteBuffer buf = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);

	private Language lang;
	private CompilerSpec cspec;
	private Trace trace;
	private TraceMemoryManager memory;
	private TraceModuleManager modules;
	private TraceThreadManager threads;
	private TraceTimeManager timeManager;

	private AddressSpace defaultSpace;

	private DebuggerTraceManagerService manager;

	private HostDataModelAccess access;
	private DebugClient client;
	private DebugControl control;
	private HDMAUtil util;

	private Set<Long> eventSnaps = new HashSet<Long>();

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

		access = DbgModel.debugCreate();
		client = access.getClient();
		control = client.getControl();
		util = new HDMAUtil(access);

		File f = askFile("Trace", "Load");

		cspec = currentProgram.getCompilerSpec();
		lang = currentProgram.getLanguage();
		defaultSpace = lang.getAddressFactory().getDefaultAddressSpace();
		trace = new DBTrace(f.getName(), cspec, this);

		memory = trace.getMemoryManager();
		modules = trace.getModuleManager();
		threads = trace.getThreadManager();
		timeManager = trace.getTimeManager();

		manager = state.getTool().getService(DebuggerTraceManagerService.class);

		client.openDumpFileWide(f.getAbsolutePath());
		control.waitForEvent();

		try (UndoableTransaction tid =
			UndoableTransaction.start(trace, "Populate Events", true)) {

			List<ModelObject> children =
				util.getElements(List.of("Debugger", "State", "DebuggerVariables", "curprocess",
					"TTD", "Events"));

			Map<String, ModelObject> maxPos = util.getAttributes(
				List.of("Debugger", "State", "DebuggerVariables", "curprocess", "TTD", "Lifetime",
					"MaxPosition"));
			Long max = (Long) maxPos.get("Sequence").getValue();

			for (ModelObject event : children) {
				Map<String, ModelObject> eventMap = event.getKeyValueMap();
				ModelObject pos = eventMap.get("Position");
				ModelObject seq = pos.getKeyValue("Sequence");
				//ModelObject step = pos.getKeyValue("Steps");
				ModelObject type = eventMap.get("Type");
				String display = type.getValueString();
				Long snap = (Long) seq.getValue();
				if (display.contains("ModuleLoaded") || display.contains("ModuleUnloaded")) {
					ModelObject module = eventMap.get("Module");
					Map<String, ModelObject> moduleMap = module.getKeyValueMap();
					ModelObject name = moduleMap.get("Name");
					ModelObject address = moduleMap.get("Address");
					ModelObject size = moduleMap.get("Size");
					String moduleId = name.getValueString();
					display += " " + moduleId;
					Address base =
						currentProgram.getAddressFactory().getAddress(address.getValueString());
					if (display.contains("ModuleLoaded")) {
						Long start = (Long) address.getValue();
						Long sz = (Long) size.getValue();
						buf = ByteBuffer.allocate(sz.intValue()).order(ByteOrder.LITTLE_ENDIAN);
						AddressRange rng = rng(start, start + sz - 1);
						modules.addLoadedModule(moduleId, moduleId, rng, snap);
						memory.addRegion(moduleId, Range.atLeast(snap), rng,
							TraceMemoryFlag.READ, TraceMemoryFlag.WRITE, TraceMemoryFlag.EXECUTE);
						try {
							int read =
								client.getDataSpaces().readVirtual(start, buf, sz.intValue());
							int written = memory.putBytes(snap, rng.getMinAddress(), buf.flip());
							if (read != written) {
								Msg.debug(this,
									"read:written=" + read + ":" + written + " at " + start);
							}
						}
						catch (Exception e) {
							System.err.println("Unable to read " + moduleId + " at " + snap);
						}
					}
					else {
						if (snap >= 0) {
							Collection<? extends TraceModule> mods =
								modules.getModulesByPath(moduleId);
							Iterator<? extends TraceModule> iterator = mods.iterator();
							while (iterator.hasNext()) {
								TraceModule next = iterator.next();
								next.setUnloadedSnap(snap);
							}
						}
					}
				}
				else if (display.contains("ThreadCreated") ||
					display.contains("ThreadTerminated")) {
					ModelObject thread = eventMap.get("Thread");
					//ModelObject uid = thread.getKeyValue("UniqueId");
					ModelObject id = thread.getKeyValue("Id");
					String threadId = id.getValueString();
					display += " " + threadId;
					if (display.contains("ThreadCreated")) {
						threads.addThread(threadId, Range.atLeast(snap));
					}
					else {
						if (snap >= 0) {
							Collection<? extends TraceThread> thrs =
								threads.getThreadsByPath(threadId);
							Iterator<? extends TraceThread> iterator = thrs.iterator();
							while (iterator.hasNext()) {
								TraceThread next = iterator.next();
								next.setDestructionSnap(snap);
							}
						}
					}
				}
				if (snap < 0) {
					snap = ++max;
				}
				timeManager.getSnapshot(snap, true).setDescription(display);
				eventSnaps.add(snap);
			}
		}

		try (UndoableTransaction tid =
			UndoableTransaction.start(trace, "Populate Registers", true)) {
			//for (Long tick : tickManager.getAllTicks()) {
			for (Long snap : eventSnaps) {
				control.execute("!tt " + Long.toHexString(snap) + ":0");
				control.waitForEvent();

				List<ModelObject> modelThreads =
					util.getElements(
						List.of("Debugger", "State", "DebuggerVariables", "curprocess", "Threads"));
				Map<String, ModelObject> modelThreadMap = new HashMap<String, ModelObject>();
				for (ModelObject obj : modelThreads) {
					modelThreadMap.put(obj.getSearchKey(), obj);
				}

				Collection<? extends TraceThread> liveThreads = threads.getLiveThreads(snap);
				for (TraceThread thread : liveThreads) {
					TraceMemoryRegisterSpace regspace = memory.getMemoryRegisterSpace(thread, true);
					ModelObject modelThread = modelThreadMap.get("0x" + thread.getName());
					if (modelThread != null) {
						Map<String, ModelObject> registers =
							modelThread.getKeyValue("Registers")
									.getKeyValue(
										"User")
									.getKeyValueMap();
						for (String rname : registers.keySet()) {
							ModelObject r = registers.get(rname);
							Register reg = reg(rname.toUpperCase());
							if (reg != null) {
								try {
									regspace.setValue(snap,
										new RegisterValue(reg, BigInteger.valueOf(
											Long.parseUnsignedLong(r.getValueString(), 16))));
								}
								catch (Exception e) {
									System.err.println(rname + "<--" + r.getValueString());
								}
							}
						}
					}
					else {
						System.err.println(thread.getName() + " not found!");
					}

				}
			}
		}

		/*
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Populate Heap", true)) {
			ModelObject currentSession = util.getCurrentSession();
			ModelObject data = currentSession.getKeyValue("TTD").getKeyValue("Data");
			ModelMethod heap = data.getMethod("Heap");
			Pointer[] args = new Pointer[0];
			ModelObject ret = heap.call(data, 0, args);
			List<TraceMemoryRegion> heapObjects = new ArrayList<TraceMemoryRegion>();
			for (ModelObject heapObj : ret.getElements()) {
				Map<String, ModelObject> heapMap = heapObj.getKeyValueMap();
				ModelObject address = heapMap.get("Address");
				ModelObject size = heapMap.get("Size");
				ModelObject timeStart = heapMap.get("TimeStart").getKeyValue("Sequence");
				ModelObject timeEnd = heapMap.get("TimeEnd").getKeyValue("Sequence");
				if (address == null) {
					continue;
				}
				Long start = (Long) address.getValue();
				if (size == null) {
					continue;
				}
				Long sz = (Long) size.getValue();
				if (sz == null) {
					continue;
				}
				AddressRange rng = rng(start, start + sz);
				String heapId = "Heap " + address.getValueString();
				Long startTick = (Long) timeStart.getValue();
				Long stopTick = (Long) timeEnd.getValue();
				Range<Long> interval =
					(stopTick > 0) ? Range.open(startTick, stopTick) : Range.atLeast(startTick);
				tickManager.setTick(startTick, heapId + " allocated");
				tickManager.setTick(stopTick, heapId + " freed");
				TraceMemoryRegion heapRegion =
					memory.addRegion(heapId, interval, rng,
						TraceMemoryFlag.READ, TraceMemoryFlag.WRITE, TraceMemoryFlag.EXECUTE);
				heapObjects.add(heapRegion);
			}
			for (TraceMemoryRegion heapRegion : heapObjects) {
				long startTick = heapRegion.getCreatedTick();
				try {
					control.execute("!tt " + Long.toHexString(startTick) + ":0");
					control.waitForEvent();
		
					AddressRange range = heapRegion.getRange();
					buf =
						ByteBuffer.allocate((int) range.getLength()).order(ByteOrder.LITTLE_ENDIAN);
					long start = range.getMinAddress().getOffset();
					int read =
						client.getDataSpaces().readVirtual(start, buf,
							(int) range.getLength());
					int written = memory.putBytes(startTick, range.getMinAddress(), buf.flip());
					if (read != written) {
						Msg.debug(this,
							"read:written=" + read + ":" + written + " at " + start);
					}
				}
				catch (Exception e) {
					System.err.println(
						"Unable to read " + heapRegion.getName() + " at " + startTick);
				}
			}
		}
		*/

		/**
		 * Give a program view to Ghidra's program manager
		 * 
		 * NOTE: Eventually, there will probably be a TraceManager service as well, but to use the
		 * familiar UI components, we generally take orders from the ProgramManager.
		 */
		manager.openTrace(trace);
		manager.activateTrace(trace);
	}

}
