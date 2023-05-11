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
package ghidra.file.formats.android.fbpk;

import java.util.List;

import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.util.task.TaskMonitor;

public abstract class FBPT implements StructConverter {

	public abstract String getMagic();

	public abstract List<FBPT_Entry> getEntries();

	public void processFBPT(Program program, Address address, TaskMonitor monitor, MessageLog log) throws Exception {
		FlatProgramAPI api = new FlatProgramAPI(program);

		DataType fbptDataType = toDataType();
		Data fbptData = program.getListing().createData(address, fbptDataType);
		if (fbptData == null) {
			log.appendMsg("Unable to apply FBPT data, stopping - " + address);
			return;
		}
		String comment = "FBPT" + "\n" + "Num of entries: " + getEntries().size();
		program.getListing().setComment(address, CodeUnit.PLATE_COMMENT, comment);
		api.createFragment(FBPK_Constants.FBPT, address, fbptDataType.getLength());
		address = address.add(fbptDataType.getLength());

		processFbPtEntries(program, address, monitor, log);
	}

	private void processFbPtEntries(Program program, Address address, TaskMonitor monitor, MessageLog log) throws Exception {
		int i = 0;
		FlatProgramAPI api = new FlatProgramAPI(program);
		for (FBPT_Entry entry : getEntries()) {
			monitor.checkCancelled();
			DataType entryDataType = entry.toDataType();
			Data entryData = program.getListing().createData(address, entryDataType);
			if (entryData == null) {
				log.appendMsg("Unable to apply FBPT Entry data, stopping - " + address);
				return;
			}
			program.getListing().setComment(address, CodeUnit.PLATE_COMMENT, entry.getName() + " - " + i++);
			api.createFragment(FBPK_Constants.FBPT, address, entryDataType.getLength());
			address = address.add(entryDataType.getLength());
		}
	}
}
