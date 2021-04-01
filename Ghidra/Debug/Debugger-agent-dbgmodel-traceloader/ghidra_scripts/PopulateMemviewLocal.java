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
import java.util.*;

import com.google.common.collect.Range;
import com.sun.jna.Pointer;

import agent.dbgeng.dbgeng.DebugClient;
import agent.dbgeng.dbgeng.DebugControl;
import agent.dbgmodel.dbgmodel.DbgModel;
import agent.dbgmodel.dbgmodel.bridge.HostDataModelAccess;
import agent.dbgmodel.dbgmodel.main.ModelMethod;
import agent.dbgmodel.dbgmodel.main.ModelObject;
import agent.dbgmodel.impl.dbgmodel.bridge.HDMAUtil;
import ghidra.app.plugin.core.debug.gui.memview.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.util.Swing;

public class PopulateMemviewLocal extends GhidraScript {

	private Language lang;

	private AddressSpace defaultSpace;

	private HostDataModelAccess access;
	private DebugClient client;
	private DebugControl control;
	private HDMAUtil util;

	private Map<String, MemoryBox> boxes = new HashMap<String, MemoryBox>();
	private Set<Long> eventSnaps = new HashSet<Long>();
	private MemviewService memview;

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

		memview = state.getTool().getService(MemviewService.class);
		if (memview == null) {
			throw new RuntimeException("Unable to find DebuggerMemviewPlugin");
		}

		access = DbgModel.debugCreate();
		client = access.getClient();
		control = client.getControl();
		util = new HDMAUtil(access);

		File f = askFile("Trace", "Load");

		lang = currentProgram.getLanguage();
		defaultSpace = lang.getAddressFactory().getDefaultAddressSpace();

		client.openDumpFileWide(f.getAbsolutePath());
		control.waitForEvent();

		List<ModelObject> children = util.getElements(
			List.of("Debugger", "State", "DebuggerVariables", "curprocess", "TTD", "Events"));

		Map<String, ModelObject> maxPos = util.getAttributes(List.of("Debugger", "State",
			"DebuggerVariables", "curprocess", "TTD", "Lifetime", "MaxPosition"));
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
				//Address base = currentProgram.getAddressFactory().getAddress(address.getValueString());
				if (display.contains("ModuleLoaded")) {
					Long start = (Long) address.getValue();
					Long sz = (Long) size.getValue();
					AddressRange rng = rng(start, start + sz - 1);
					addLoadedModule(moduleId, moduleId, Range.atLeast(snap), rng);
					//addRegion(moduleId, Range.atLeast(snap), rng, TraceMemoryFlag.READ,
					//	TraceMemoryFlag.WRITE, TraceMemoryFlag.EXECUTE);
				}
				else {
					markModuleClosed(moduleId, snap);
				}
			}
			else if (display.contains("ThreadCreated") || display.contains("ThreadTerminated")) {
				ModelObject thread = eventMap.get("Thread");
				//ModelObject uid = thread.getKeyValue("UniqueId");
				ModelObject id = thread.getKeyValue("Id");
				String threadId = id.getValueString();
				int iid = Integer.parseInt(threadId, 16);
				AddressRange rng = rng(iid, iid + 1);
				display += " " + threadId;
				if (display.contains("ThreadCreated")) {
					addThread("Thread " + threadId, Range.atLeast(snap), rng);
				}
				else {
					markThreadClosed(threadId, snap);
				}
			}
			if (snap < 0) {
				snap = ++max;
			}
			//timeManager.getSnapshot(snap, true).setDescription(display);
			eventSnaps.add(snap);
		}

		for (Long snap : eventSnaps) {
			control.execute("!tt " + Long.toHexString(snap) + ":0");
			control.waitForEvent();

			List<ModelObject> modelThreads = util.getElements(
				List.of("Debugger", "State", "DebuggerVariables", "curprocess", "Threads"));
			Map<String, ModelObject> modelThreadMap = new HashMap<String, ModelObject>();
			for (ModelObject obj : modelThreads) {
				modelThreadMap.put(obj.getSearchKey(), obj);
			}
		}

		ModelObject currentSession = util.getCurrentSession();
		ModelObject data = currentSession.getKeyValue("TTD").getKeyValue("Data");
		ModelMethod heap = data.getMethod("Heap");
		Pointer[] args = new Pointer[0];
		ModelObject ret = heap.call(data, 0, args);
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
			addHeap(heapId, interval, rng, TraceMemoryFlag.READ, TraceMemoryFlag.WRITE,
				TraceMemoryFlag.EXECUTE);
		}

		/**
		 * Give a program view to Ghidra's program manager
		 * 
		 * NOTE: Eventually, there will probably be a TraceManager service as well, but to use the
		 * familiar UI components, we generally take orders from the ProgramManager.
		 */
		//manager.openTrace(trace);
		//manager.activateTrace(trace);
		List<MemoryBox> boxList = new ArrayList<>();
		for (MemoryBox memoryBox : boxes.values()) {
			boxList.add(memoryBox);
		}
		Swing.runIfSwingOrRunLater(() -> {
			memview.setBoxes(boxList);
			memview.setProgram(currentProgram);
			memview.initViews();
		});
	}

	private void addHeap(String heapId, Range<Long> interval, AddressRange rng,
			TraceMemoryFlag read, TraceMemoryFlag write, TraceMemoryFlag execute) {
		MemoryBox box = new MemoryBox(heapId, MemviewBoxType.HEAP_CREATE, rng, interval);
		boxes.put(box.getId(), box);
	}

	private void addThread(String threadId, Range<Long> interval, AddressRange rng) {
		MemoryBox box = new MemoryBox(threadId, MemviewBoxType.THREAD, rng, interval);
		boxes.put(box.getId(), box);
	}

	private void addRegion(String regionId, Range<Long> interval, AddressRange rng,
			TraceMemoryFlag read, TraceMemoryFlag write, TraceMemoryFlag execute) {
		MemoryBox box = new MemoryBox(regionId, MemviewBoxType.IMAGE, rng, interval);
		boxes.put(box.getId(), box);
	}

	private void addLoadedModule(String moduleId, String moduleId2, Range<Long> interval,
			AddressRange rng) {
		MemoryBox box = new MemoryBox(moduleId, MemviewBoxType.MODULE, rng, interval);
		boxes.put(box.getId(), box);
	}

	private void markThreadClosed(String threadId, Long end) {
		MemoryBox box = boxes.get(threadId);
		if (box != null) {
			if (end < 0) {
				end = Long.MAX_VALUE;
			}
			box.setEnd(end);
		}
	}

	private void markModuleClosed(String moduleId, Long end) {
		MemoryBox box = boxes.get(moduleId);
		if (box != null) {
			if (end < 0) {
				end = Long.MAX_VALUE;
			}
			box.setEnd(end);
		}
	}

}
