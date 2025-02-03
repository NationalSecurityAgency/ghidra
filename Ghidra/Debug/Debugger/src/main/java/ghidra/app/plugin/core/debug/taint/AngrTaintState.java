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
package ghidra.app.plugin.core.debug.taint;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.util.Collection;
import java.util.List;

import ghidra.app.decompiler.ClangFuncNameToken;
import ghidra.app.plugin.core.decompiler.taint.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.ConsoleService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighParam;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;

/**
 * Container for all the decompiler elements the users "selects" via the menu.
 * This data is used to build queries.
 */
public class AngrTaintState extends AbstractTaintState {

	private DebuggerTraceManagerService traceManager;

	public AngrTaintState(TaintPlugin plugin) {
		super(plugin);
		ENGINE_NAME = "angr";
		usesIndex = false;
	}

	private Address start;

	@Override
	public void buildQuery(List<String> paramList, Path engine, File indexDBFile,
			String indexDirectory) {
		paramList.add("python");
		paramList.add(engine.toString());
	}

	@Override
	public void buildIndex(List<String> paramList, String engine_path, String facts_path,
			String indexDirectory) {
		// Unused
	}

	@Override
	public GhidraScript getExportScript(ConsoleService console, boolean perFunction) {
		return null;
	}

	@Override
	protected void writeHeader(PrintWriter writer) {
		Program currentProgram = plugin.getCurrentProgram();
		start = currentProgram.getMaxAddress().getNewAddress(Integer.MAX_VALUE);
		writer.println("{");
		writer.println("\t\"binary_file\":\"" + currentProgram.getExecutablePath() + "\",");
		writer.println("\t\"base_address\":\"" +
			Long.toHexString(currentProgram.getImageBase().getOffset()) + "\",");
	}

	/*
	 * NOTE: This is the only method used now for Sources and Sinks.
	 */
	@Override
	protected void writeRule(PrintWriter writer, TaintLabel mark, boolean isSource) {
		Program currentProgram = plugin.getCurrentProgram();
		Address addr = mark.getAddress();
		if (isSource) {
			if (start.getOffset() > addr.getOffset()) {
				start = addr;
			}
		}
		else {
			writer.println("\t\"find_address\":\"" + Long.toHexString(addr.getOffset()) + "\",");
			return;
		}

		if (isSource) {
			if (mark.getToken() instanceof ClangFuncNameToken) {
				CodeUnit cu = currentProgram.getListing().getCodeUnitAt(addr);
				writer.println("\t\"hooks\":[{\"" + Long.toHexString(addr.getOffset()) +
					"\":{\"length\":\"" + cu.getLength() + "\"}}],");
				return;
			}
			if (mark.getHighVariable() instanceof HighParam hp) {
				writer.println(
					"\t\"arguments\":{\"" + hp.getSlot() + "\":\"" + mark.getSize() + "\"},");
				return;
			}
			Address vaddr = mark.getVarnodeAddress();
			if (vaddr != null) {
				if (vaddr.isRegisterAddress()) {
					Language language = currentProgram.getLanguage();
					Register register = language.getRegister(vaddr, mark.getSize());
					writer.println("\t\"regs_vals\":{\"" + register.getName() + "\":\"" +
						mark.getSize() + "\"},");
				}
				if (vaddr.isMemoryAddress()) {
					writer.println("\t\"vectors\":{\"" + vaddr + "\":\"" + mark.getSize() + "\"},");
				}
			}
		}

	}

	@Override
	public void writeGate(PrintWriter writer, TaintLabel mark) {
		Address addr = mark.getAddress();
		writer.println("\t\"avoid_address\":\"" + Long.toHexString(addr.getOffset()) + "\",");
	}

	@Override
	protected void writeFooter(PrintWriter writer) {
		writeState(writer);
		writer.println("\t\"blank_state\":\"" + Long.toHexString(start.getOffset()) + "\",");
		writer.println("\t\"auto_load_libs\":false");
		writer.println("}");
	}

	private void writeState(PrintWriter writer) {
		if (traceManager == null) {
			traceManager = plugin.getTool().getService(DebuggerTraceManagerService.class);
			if (traceManager == null) {
				return;
			}
		}
		DebuggerCoordinates current = traceManager.getCurrent();
		Trace trace = current.getTrace();
		if (trace == null) {
			return;
		}

		TraceMemoryManager memoryManager = trace.getMemoryManager();
		Collection<? extends TraceMemoryRegion> allRegions =
			memoryManager.getRegionsAtSnap(current.getSnap());
		for (TraceMemoryRegion region : allRegions) {
			AddressRange range = region.getRange();
			Address min = range.getMinAddress();
			int len = (int) range.getLength();
			byte[] bytes = new byte[len];
			int nread =
				memoryManager.getBytes(current.getSnap(), min, ByteBuffer.wrap(bytes));
			if (nread == len) {
				writer.println("\t\"mem_store\":{\"" + min + "\":\"" + convert(bytes) + "\"},");
			}
			else {
				Msg.error(this, "Requested " + len + " but returned " + nread);
			}
		}

		Program currentProgram = plugin.getCurrentProgram();
		List<Register> registers = currentProgram.getLanguage().getRegisters();
		TraceThread thread = current.getThread();
		if (thread == null) {
			return;
		}
		TraceMemorySpace regs =
			memoryManager.getMemoryRegisterSpace(thread, current.getFrame(), true);
		if (regs == null) {
			return;
		}
		for (Register r : registers) {
			TraceMemoryState state = regs.getState(current.getPlatform(), current.getSnap(), r);
			if (!state.equals(TraceMemoryState.KNOWN)) {
				continue;
			}
			RegisterValue value = regs.getValue(current.getSnap(), r);
			byte[] bytes = value.getUnsignedValue().toByteArray();
			String bytestr = convert(bytes);
			if (!bytestr.equals("") && !bytestr.equals("00")) {
				writer.println(
					"\t\"regs_vals\":{\"" + r.getName() + "\":\"0x" + convert(bytes) + "\"},");
			}
		}
	}

	private String convert(byte[] bytes) {
		return NumericUtilities.convertBytesToString(bytes);
	}


	@Override
	protected void readQueryResultsIntoDataFrame(Program program, InputStream is) {

		Program currentProgram = plugin.getCurrentProgram();
		String line = null;
		taintAddressSet.clear();
		taintVarnodeMap.clear();

		try {
			BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(is));

			while ((line = bufferedReader.readLine()) != null) {
				if (line.startsWith("t:")) {
					String addrStr = line.substring(line.indexOf(":") + 1);
					Address address = currentProgram.getMinAddress().getAddress(addrStr);
					taintAddressSet.add(address);
				}
				else {
					System.err.println(line);
				}
			}
			bufferedReader.close();
		}
		catch (IOException | AddressFormatException e) {
			plugin.consoleMessage("IO Error Reading Query Results from Process: " + e.getMessage());
		}
	}

}
