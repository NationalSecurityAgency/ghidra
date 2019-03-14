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
package ghidra.app.cmd.formats;

import ghidra.app.plugin.core.analysis.AnalysisWorker;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.coff.archive.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.cmd.BinaryAnalysisCommand;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.NotEmptyException;
import ghidra.util.task.TaskMonitor;

public class CoffArchiveBinaryAnalysisCommand extends FlatProgramAPI
		implements BinaryAnalysisCommand, AnalysisWorker {
	private MessageLog messages = new MessageLog();

	public CoffArchiveBinaryAnalysisCommand() {
		super();
	}

	@Override
	public boolean analysisWorkerCallback(Program program, Object workerContext,
			TaskMonitor monitor) throws Exception, CancelledException {

		ByteProvider provider = new MemoryByteProvider(currentProgram.getMemory(),
			currentProgram.getAddressFactory().getDefaultAddressSpace());

		if (!CoffArchiveHeader.isMatch(provider)) {
			return false;
		}

		CoffArchiveHeader header = CoffArchiveHeader.read(provider, monitor);
		applyDataTypes(provider, header);
		removeEmptyFragments();
		return true;
	}

	@Override
	public String getWorkerName() {
		return getName();
	}

	@Override
	public boolean applyTo(Program program, TaskMonitor monitor) throws Exception {
		set(program, monitor);

		// Modify program and prevent events from triggering follow-on analysis
		AutoAnalysisManager aam = AutoAnalysisManager.getAnalysisManager(currentProgram);
		return aam.scheduleWorker(this, null, false, monitor);
	}

	@Override
	public boolean canApply(Program program) {
		try {
			Memory memory = program.getMemory();
			byte[] magicBytes = new byte[CoffArchiveConstants.MAGIC_LEN];
			memory.getBytes(program.getAddressFactory().getDefaultAddressSpace().getAddress(0),
				magicBytes);
			String magic = new String(magicBytes);
			return CoffArchiveConstants.MAGIC.equals(magic);
		}
		catch (Exception e) {
			// expected, ignore
		}
		return false;
	}

	@Override
	public MessageLog getMessages() {
		return messages;
	}

	@Override
	public String getName() {
		return "COFF Archive Header Annotation";
	}

	private void removeEmptyFragments() throws NotEmptyException {
		monitor.setMessage("Removing empty fragments...");
		String[] treeNames = currentProgram.getListing().getTreeNames();
		for (String treeName : treeNames) {
			if (monitor.isCancelled()) {
				break;
			}
			ProgramModule rootModule = currentProgram.getListing().getRootModule(treeName);
			Group[] children = rootModule.getChildren();
			for (Group child : children) {
				if (monitor.isCancelled()) {
					break;
				}
				if (child instanceof ProgramFragment) {
					ProgramFragment fragment = (ProgramFragment) child;
					if (fragment.isEmpty()) {
						rootModule.removeChild(fragment.getName());
					}
				}
			}
		}
	}

	private void applyDataTypes(ByteProvider provider, CoffArchiveHeader header) throws Exception {
		markupArchiveHeader(header);
		markupArchiveMemberHeader(provider, header);
		markupFirstLinkerMember(header);
		markupSecondLinkerMember(header);
		markupLongNamesMember(header);
	}

	private void markupLongNamesMember(CoffArchiveHeader header) throws Exception {
		LongNamesMember longNamesMember = header.getLongNameMember();
		if (longNamesMember == null) {
			return;
		}
		DataType dt = longNamesMember.toDataType();
		Address start = toAddr(longNamesMember.getFileOffset());
		createData(start, dt);
		createFragment(dt.getName(), start, dt.getLength());
	}

	private void markupSecondLinkerMember(CoffArchiveHeader header) throws Exception {
		SecondLinkerMember secondLinkerMember = header.getSecondLinkerMember();
		if (secondLinkerMember == null) {
			return;
		}
		DataType dt = secondLinkerMember.toDataType();
		Address start = toAddr(secondLinkerMember.getFileOffset());
		createData(start, dt);
		createFragment(dt.getName(), start, dt.getLength());
	}

	private void markupFirstLinkerMember(CoffArchiveHeader header) throws Exception {
		FirstLinkerMember firstLinkerMember = header.getFirstLinkerMember();
		if (firstLinkerMember == null) {
			return;
		}
		DataType dt = firstLinkerMember.toDataType();
		Address start = toAddr(firstLinkerMember.getFileOffset());
		createData(start, dt);
		createFragment(dt.getName(), start, dt.getLength());
	}

	private void markupArchiveMemberHeader(ByteProvider provider, CoffArchiveHeader header)
			throws Exception {

		for (CoffArchiveMemberHeader archiveMemberHeader : header.getArchiveMemberHeaders()) {
			if (monitor.isCancelled()) {
				break;
			}
			DataType dt = archiveMemberHeader.toDataType();
			Address start = toAddr(archiveMemberHeader.getFileOffset());
			Address end = start.add(dt.getLength());
			createData(start, dt);
			createFragment("ArchiveMemberHeader", start, dt.getLength());

			if (!archiveMemberHeader.isCOFF()) {
				continue;
			}

			String name = SymbolUtilities.replaceInvalidChars(archiveMemberHeader.getName(), true);

			Address payloadAddress = end;
			createFragment(name, payloadAddress, archiveMemberHeader.getSize());
			createLabel(payloadAddress, name, true);
		}
	}

	private void markupArchiveHeader(CoffArchiveHeader header) throws Exception {
		DataType dt = header.toDataType();
		createData(toAddr(0), dt);
		createFragment("ArchiveHeader", toAddr(0), dt.getLength());
	}
}
