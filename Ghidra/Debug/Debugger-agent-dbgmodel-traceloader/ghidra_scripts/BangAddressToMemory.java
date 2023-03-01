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
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import agent.dbgeng.manager.impl.DbgManagerImpl;
import agent.dbgeng.model.AbstractDbgModel;
import db.Transaction;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.DebuggerModelService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.*;
import ghidra.util.LockHold;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

/**
 * This script populates a trace database with memory derived from "!address". This is particularly
 * useful for dump files and other cases where QueryVirtual fails.
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
 */
public class BangAddressToMemory extends GhidraScript {

	/**
	 * The Memory APIs all use Java NIO ByteBuffer. While it has it can sometimes be annoying, it
	 * provides most of the conveniences you'd need for packing arbitrary data into a memory buffer.
	 * I'll allocate one here large enough to write a couple values at a time.
	 */
	private ByteBuffer buf = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);

	private Language lang;
	private Trace trace;
	private TraceMemoryManager memory;

	private AddressSpace defaultSpace;

	private DebuggerModelService modelService;
	private DebuggerTraceManagerService managerService;

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

	@Override
	protected void run() throws Exception {

		modelService = state.getTool().getService(DebuggerModelService.class);
		if (modelService == null) {
			throw new RuntimeException("Unable to find DebuggerMemviewPlugin");
		}

		DebuggerObjectModel model = modelService.getCurrentModel();
		if (!(model instanceof AbstractDbgModel)) {
			throw new RuntimeException("Current model must be an AbstractDbgModel");
		}
		AbstractDbgModel dbgmodel = (AbstractDbgModel) model;
		DbgManagerImpl manager = (DbgManagerImpl) dbgmodel.getManager();
		//client = manager.getClient();

		managerService = state.getTool().getService(DebuggerTraceManagerService.class);
		trace = managerService.getCurrentTrace();
		if (trace == null) {
			throw new RuntimeException("Script requires an active trace");
		}
		memory = trace.getMemoryManager();

		lang = currentProgram.getLanguage();
		defaultSpace = lang.getAddressFactory().getDefaultAddressSpace();

		manager.consoleCapture("!address").thenAccept(result -> {
			parse(result);
		});
	}

	private void parse(String result) {
		try (Transaction tx = trace.openTransaction("Populate memory");
				LockHold hold = trace.lockWrite();) {
			//Pattern pattern = Pattern.compile("\\s+(*)\\s+(*)\\s+");
			//Matcher matcher = pattern.matcher(fullclassname);
			String[] lines = result.split("\n");
			for (String line : lines) {
				if (line.startsWith("Mapping")) {
					continue;
				}
				String[] fields = line.trim().split("\\s+");
				if (fields.length < 4) {
					continue;
				}
				String startStr = fields[0].replaceAll("`", "");
				String endStr = fields[1].replaceAll("`", "");
				long start, end;
				try {
					start = Long.parseUnsignedLong(startStr, 16);
					end = Long.parseUnsignedLong(endStr, 16);
				}
				catch (Exception e) {
					continue;
				}
				String name = fields[3];
				AddressRange rng = rng(start, end - 1);
				try {
					TraceMemoryRegion region =
						memory.addRegion(startStr, Lifespan.nowOn(0), rng, TraceMemoryFlag.READ,
							TraceMemoryFlag.WRITE, TraceMemoryFlag.EXECUTE);
					region.setName(name);
				}
				catch (TraceOverlappedRegionException | DuplicateNameException e) {
					Msg.info(this, "Duplicate range at " + start);
				}
			}
		}
	}
}
