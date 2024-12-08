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
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.gson.JsonArray;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import sarif.SarifProgramOptions;
import sarif.export.SarifWriterTask;
import sarif.export.registers.SarifRegisterValueWriter;

/**
 * SARIF manager for register values.
 */
public class RegisterValuesSarifMgr extends SarifMgr {

	public static String KEY = "REGISTER_VALUES";
	public static String SUBKEY = "Registers";

	private ProgramContext context;
	private Set<String> undefinedRegisterNames;

	RegisterValuesSarifMgr(Program program, MessageLog log) {
		super(KEY, program, log);
		context = program.getProgramContext();
	}

	////////////////////////////
	// SARIF READ CURRENT DTD //
	////////////////////////////

	@Override
	public boolean read(Map<String, Object> result, SarifProgramOptions options, TaskMonitor monitor)
			throws CancelledException {
		processRegisterValues(result);
		return true;
	}

	/**
	 * Returns list of unique registers which do not overlap any smaller registers.
	 */
	private List<Register> getUniqueRegisters() {

		ArrayList<Register> regs = new ArrayList<>(context.getRegisters());
		Collections.sort(regs, new Comparator<Register>() {
			@Override
			public int compare(Register r1, Register r2) {
				int size1 = r1.getMinimumByteSize();
				int size2 = r2.getMinimumByteSize();
				if (size1 != size2) {
					return size1 - size2;
				}
				return r1.getOffset() - r2.getOffset();
			}
		});

		return regs;
	}

	private void processRegisterValues(Map<String, Object> result) {
		try {
			AddressSet set = getLocations(result, null);
			Address addr = set.getMinAddress();
			int len = (int) set.getMaxAddress().subtract(addr) + 1;
			String regName = (String) result.get("name");
			String valueStr = (String) result.get("value");
			if (valueStr.startsWith("0x") || valueStr.startsWith("0X")) {
				valueStr = valueStr.substring(2);
			}
			BigInteger value = new BigInteger(valueStr, 16);

			Register reg = context.getRegister(regName);
			if (reg == null) {
				if (undefinedRegisterNames.add(regName)) {
					log.appendMsg("REGISTER [" + regName + "] is not defined by " + program.getLanguageID()
							+ ", register values will be ignored");
				}
				return;
			}

			context.setValue(reg, addr, addr.addNoWrap(len - 1), value);
		} catch (Exception e) {
			log.appendException(e);
		}
	}

	/////////////////////////////
	// SARIF WRITE CURRENT DTD //
	/////////////////////////////

	/**
	 * Write out the SARIF for the Equates.
	 * 
	 * @param results writer for SARIF
	 * @param set     address set that is either the entire program or a selection
	 * @param monitor monitor that can be canceled should be written
	 * @throws IOException
	 */
	void write(JsonArray results, AddressSetView set, TaskMonitor monitor) throws IOException, CancelledException {

		List<Register> regs = getUniqueRegisters();
		if (set == null) {
			set = program.getMemory();
		}
		List<AddressRange> request = new ArrayList<>();
		AddressRangeIterator rangeIter = set.getAddressRanges();
		while (rangeIter.hasNext()) {
			monitor.checkCancelled();
			request.add(rangeIter.next());
		}

		writeAsSARIF(context, regs, request, results);
	}

	public static void writeAsSARIF(ProgramContext context, List<Register> registers, List<AddressRange> request,
			JsonArray results) throws IOException {
		SarifRegisterValueWriter writer = new SarifRegisterValueWriter(context, registers, request, null);
		new TaskLauncher(new SarifWriterTask(SUBKEY, writer, results), null);
	}

}
