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
package ghidra.file.formats.android.fbpk.v2;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.importer.MessageLog;
import ghidra.file.formats.android.fbpk.FBPK_Constants;
import ghidra.file.formats.android.fbpk.FBPK_Partition;
import ghidra.file.formats.android.fbpk.FBPT;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class FBPKv2_Partition extends FBPK_Partition {

	private long offset;
	private int unknown1;
	private int size;
	private int unknown2;
	private int paritionType;
	private int unknown3;

	private FBPT fbpt;
	private UFPK ufpk;
	private UFSM ufsm;
	private UFSP ufsp;

	public FBPKv2_Partition(BinaryReader reader) throws IOException {
		long start = reader.getPointerIndex();

		type = reader.readNextInt();
		name = reader.readNextAsciiString(FBPK_Constants.V2_PARTITION_NAME_MAX_LENGTH);
		offset = reader.readNextInt();
		unknown1 = reader.readNextInt();
		size = reader.readNextInt();
		unknown2 = reader.readNextInt();
		paritionType = reader.readNextInt();
		unknown3 = reader.readNextInt();

		headerSize = (int) (reader.getPointerIndex() - start);

		BinaryReader clone = reader.clone(offset);

		if (paritionType == 0) {
			if (name.startsWith(FBPK_Constants.V2_PARTITION)) {
				fbpt = new FBPTv2(clone);
			}
			if (name.equals(FBPK_Constants.V2_UFS)) {
				if (clone.peekNextInt() == FBPK_Constants.UFSM_MAGIC) {
					ufsm = new UFSM(clone);
				}
				else if (clone.peekNextInt() == FBPK_Constants.UFSP_MAGIC) {
					ufsp = new UFSP(clone);
				}
			}
			if (name.equals(FBPK_Constants.V2_UFSFWUPDATE)) {
				ufpk = new UFPK(clone);
			}
		}
	}

	@Override
	public long getDataStartOffset() {
		return offset;
	}

	@Override
	public int getDataSize() {
		return size;
	}

	public FBPT getFBPT() {
		return fbpt;
	}

	public UFPK getUFPK() {
		return ufpk;
	}

	public UFSM getUFSM() {
		return ufsm;
	}

	public UFSP getUFSP() {
		return ufsp;
	}

	public int getUnknown1() {
		return unknown1;
	}

	public int getUnknown2() {
		return unknown2;
	}

	public int getParitionType() {
		return paritionType;
	}

	public int getUnknown3() {
		return unknown3;
	}

	@Override
	public boolean isFile() {
		return paritionType == FBPK_Constants.PARTITION_TYPE_FILE;
	}

	@Override
	public int getOffsetToNextPartitionTable() {
		return 0;
	}

	@Override
	public void markup(Program program, Address address, TaskMonitor monitor, MessageLog log)
			throws Exception {

		super.markup(program, address, monitor, log);

		processFBPT(program, monitor, log);
		processUFPK(program, monitor, log);
		processUFSM(program, monitor, log);
		processUFSP(program, monitor, log);
	}

	private void processFBPT(Program program, TaskMonitor monitor, MessageLog log)
			throws Exception {

		Address address = program.getMinAddress().getNewAddress(offset);

		if (fbpt != null) {
			fbpt.processFBPT(program, address, monitor, log);
		}
	}

	private void processUFPK(Program program, TaskMonitor monitor, MessageLog log)
			throws Exception {

		Address address = program.getMinAddress().getNewAddress(offset);

		if (ufpk != null) {
			DataType dataType = ufpk.toDataType();
			Data data = program.getListing().createData(address, dataType);
			if (data == null) {
				log.appendMsg("Unable to apply " + FBPK_Constants.UFPK_MAGIC +
					" data, stopping - " + address);
			}
		}
	}

	private void processUFSM(Program program, TaskMonitor monitor, MessageLog log)
			throws Exception {

		Address address = program.getMinAddress().getNewAddress(offset);

		if (ufsm != null) {
			DataType dataType = ufsm.toDataType();
			Data data = program.getListing().createData(address, dataType);
			if (data == null) {
				log.appendMsg(
					"Unable to apply " + FBPK_Constants.UFSM + " data, stopping - " + address);
			}
		}
	}

	private void processUFSP(Program program, TaskMonitor monitor, MessageLog log)
			throws Exception {

		Address address = program.getMinAddress().getNewAddress(offset);

		if (ufsp != null) {
			DataType dataType = ufsp.toDataType();
			Data data = program.getListing().createData(address, dataType);
			if (data == null) {
				log.appendMsg(
					"Unable to apply " + FBPK_Constants.UFSP + " data, stopping - " + address);
			}
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType(FBPKv2_Partition.class.getSimpleName(), 0);
		struct.add(DWORD, "type", null);
		struct.add(STRING, FBPK_Constants.V2_PARTITION_NAME_MAX_LENGTH, "name", null);
		struct.add(DWORD, "offset", null);
		struct.add(DWORD, "unknown1", null);
		struct.add(DWORD, "size", null);
		struct.add(DWORD, "unknown2", null);
		struct.add(DWORD, "paritionType", null);
		struct.add(DWORD, "unknown3", null);
		return struct;
	}
}
