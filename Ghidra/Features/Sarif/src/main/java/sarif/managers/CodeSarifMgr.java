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
package sarif.managers;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.google.gson.JsonArray;

import generic.stl.Pair;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerMessageListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import sarif.SarifProgramOptions;
import sarif.export.SarifWriterTask;
import sarif.export.code.SarifCodeWriter;

public class CodeSarifMgr extends SarifMgr implements DisassemblerMessageListener {

	public static String KEY = "CODE";
	public static String SUBKEY = "Code";
	public static String SUBKEY2 = "Override";

	public CodeSarifMgr(Program program, MessageLog log) {
		super(KEY, program, log);
	}

	////////////////////////////
	// SARIF READ CURRENT DTD //
	////////////////////////////

	@Override
	public boolean read(Map<String, Object> result, SarifProgramOptions options, TaskMonitor monitor)
			throws CancelledException {

		AddressSet set = new AddressSet();

		try {
			getLocations(result, set);
		} catch (AddressOverflowException e) {
			log.appendException(e);
		}

		String msg = (String) result.get("Message");

		AddressSet disset = set.intersect(program.getMemory());
		if (!disset.equals(set)) {
			log.appendMsg("Disassembly address set changed to " + disset.toString());
		}
		disassemble(disset, monitor);

		if (msg.equals(SUBKEY2)) {
			Instruction inst = program.getListing().getInstructionAt(set.getMinAddress());
			String override = (String) result.get("kind");
			inst.setFlowOverride(FlowOverride.valueOf(override));
		}
		return true;
	}

	public void disassemble(AddressSet set, TaskMonitor monitor) {
		Disassembler disassembler = Disassembler.getDisassembler(program, monitor, this);
		try {
			Listing listing = program.getListing();
			while (!set.isEmpty() && !monitor.isCancelled()) {
				Address start = set.getMinAddress();
				AddressSet disset = disassembler.disassemble(start, set);
				if (disset.isEmpty()) {
					Instruction instr = listing.getInstructionAt(start);
					if (instr == null) {
						AddressRange skipRange = set.iterator().next();
						log.appendMsg("Expected valid Instruction at " + start);
						log.appendMsg("...skipping code range " + skipRange.getMinAddress() + " to "
								+ skipRange.getMaxAddress());
						set.delete(skipRange);
					} else {
						set.deleteRange(instr.getMinAddress(), instr.getMaxAddress());
					}
				} else {
					set.delete(disset);
				}
			}
		} catch (Exception e) {
			log.appendMsg("Error during disassembly: " + e.getMessage());
		}
	}

	@Override
	public void disassembleMessageReported(String msg) {
		log.appendMsg("Error from disassembler: " + msg);
	}

	/////////////////////////////
	// SARIF WRITE CURRENT DTD //
	/////////////////////////////

	void write(JsonArray results, AddressSetView set, TaskMonitor monitor) throws IOException, CancelledException {
		monitor.setMessage("Writing CODE ...");

		List<AddressRange> request = new ArrayList<>();
		List<Pair<Instruction, FlowOverride>> requestOverride = new ArrayList<>();
		InstructionIterator it = null;
		if (set == null) {
			it = program.getListing().getInstructions(true);
		} else {
			it = program.getListing().getInstructions(set, true);
		}

		while (it.hasNext()) {
			Instruction inst = it.next();
			Address start = inst.getMinAddress();
			Address end = inst.getMaxAddress();
			while (it.hasNext()) {
				inst = it.next();
				FlowOverride override = inst.getFlowOverride();
				if (!override.equals(FlowOverride.NONE)) {
					requestOverride.add(new Pair<Instruction, FlowOverride>(inst, override));
				}

				if (!end.isSuccessor(inst.getMinAddress())) {
					request.add(new AddressRangeImpl(start, end));
					start = inst.getMinAddress();
				}
				end = inst.getMaxAddress();
				monitor.checkCancelled();
			}
			request.add(new AddressRangeImpl(start, end));
		}

		writeAsSARIF(request, requestOverride, results);
	}

	public static void writeAsSARIF(List<AddressRange> request, List<Pair<Instruction, FlowOverride>> request2,
			JsonArray results) throws IOException {
		SarifCodeWriter writer = new SarifCodeWriter(request, request2, null);
		new TaskLauncher(new SarifWriterTask(SUBKEY, writer, results), null);
	}

}
