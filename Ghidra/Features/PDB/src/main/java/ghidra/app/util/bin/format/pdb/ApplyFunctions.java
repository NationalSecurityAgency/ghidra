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
package ghidra.app.util.bin.format.pdb;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.XmlUtilities;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

class ApplyFunctions {

	private ApplyFunctions() {
		// static use only
	}

	/**
	 * Perform parsing and applying of functions 
	 * @param pdbParser PDB parser object
	 * @param xmlParser XML parser position immediately after the functions start element
	 * @param monitor task monitor
	 * @param log message log
	 * @throws CancelledException if task cancelled
	 */
	static void applyTo(PdbParser pdbParser, XmlPullParser xmlParser, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		Program program = pdbParser.getProgram();
		Listing listing = program.getListing();
		while (xmlParser.hasNext()) {
			if (monitor.isCancelled()) {
				return;
			}
			XmlElement child = xmlParser.next();
			if (child.isEnd() && child.getName().equals("functions")) {
				break;
			}

			String name = child.getAttribute("name");
			int addr = XmlUtilities.parseInt(child.getAttribute("address"));

			Address address = PdbUtil.reladdr(program, addr);

			monitor.setMessage("Applying function at " + address + "...");

//TODO handle functions inside jmps (see pdb_test.exe 0x41100a

			Instruction instr = listing.getInstructionAt(address);
			if (instr == null) {
				DisassembleCommand cmd = new DisassembleCommand(address, null, true);
				cmd.applyTo(program, monitor);
			}

			pdbParser.createSymbol(address, name, true, log);

			Function function = listing.getFunctionAt(address);
			if (function == null) {
				function = createFunction(program, address);
			}
			if (function == null) {
				function = checkInsideThunkJump(program, address, monitor);
			}
			if (function == null) {
				function = checkInsideThunkFunction(program, address, monitor);
			}
			if (function == null) {
				xmlParser.discardSubTree(child);
				continue;
			}

			ApplyStackVariables applyStackVariables =
				new ApplyStackVariables(pdbParser, xmlParser, function);
			applyStackVariables.applyTo(monitor, log);

			ApplyLineNumbers applyLineNumbers = new ApplyLineNumbers(pdbParser, xmlParser, program);
			applyLineNumbers.applyTo(monitor, log);

			xmlParser.next();//skip function end element
		}
	}

	private static Function checkInsideThunkFunction(Program program, Address address,
			TaskMonitor monitor) throws CancelledException {
		Listing listing = program.getListing();
		Function thunkFunction = listing.getFunctionContaining(address);
		if (thunkFunction == null) {
			return null;
		}
		if (thunkFunction.getEntryPoint().equals(address)) {
			return null;
		}
		AddressSet thunkBody = new AddressSet(thunkFunction.getBody());
		boolean hasRangeMatch = true;
		AddressRangeIterator ari = thunkBody.getAddressRanges(true);
		while (ari.hasNext()) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			AddressRange range = ari.next();
			if (range.getMinAddress().equals(address)) {
				hasRangeMatch = true;
				thunkBody.delete(range);
				break;
			}
		}
		if (!hasRangeMatch) {
			return null;
		}
		try {
			thunkFunction.setBody(thunkBody);
		}
		catch (OverlappingFunctionException e) {
			//should never happen...
		}
		Function newFunction = createFunction(program, address);
		thunkFunction.setThunkedFunction(newFunction);
		return newFunction;
	}

	private static Function checkInsideThunkJump(Program program, Address address,
			TaskMonitor monitor) throws CancelledException {
		Listing listing = program.getListing();
		List<Reference> refList = getReferencesTo(program, address, monitor);
		if (refList.size() != 1) {//sanity check...
			return null;
		}
		Address thunkAddress = refList.get(0).getFromAddress();
		Function thunkFunction = listing.getFunctionAt(thunkAddress);
		if (thunkFunction == null) {
			return null;
		}
		Instruction thunkInstr = listing.getInstructionAt(thunkAddress);
		if (thunkInstr.getFlowType().isJump()) {
			AddressSetView newThunkBody =
				new AddressSet(thunkInstr.getMinAddress(), thunkInstr.getMaxAddress());
			try {
				thunkFunction.setBody(newThunkBody);
			}
			catch (OverlappingFunctionException e) {
				//should never happen...
			}
		}
		Function newFunction = createFunction(program, address);
		thunkFunction.setThunkedFunction(newFunction);
		return newFunction;
	}

	private static List<Reference> getReferencesTo(Program program, Address address,
			TaskMonitor monitor) throws CancelledException {
		List<Reference> refList = new ArrayList<>();
		ReferenceManager refMgr = program.getReferenceManager();
		ReferenceIterator refIter = refMgr.getReferencesTo(address);
		while (refIter.hasNext()) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			refList.add(refIter.next());
		}
		return refList;
	}

	private static Function createFunction(Program program, Address entryPoint) {
		CreateFunctionCmd fCmd = new CreateFunctionCmd(entryPoint);
		fCmd.applyTo(program);
		return program.getListing().getFunctionAt(entryPoint);
	}
}
