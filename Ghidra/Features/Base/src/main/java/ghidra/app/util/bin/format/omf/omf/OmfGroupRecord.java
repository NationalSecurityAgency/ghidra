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
package ghidra.app.util.bin.format.omf.omf;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.omf.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Language;
import ghidra.util.exception.DuplicateNameException;

public class OmfGroupRecord extends OmfRecord {
	private OmfIndex groupNameIndex;
	private String groupName;
	private long vma = -1;		// Assigned (by linker) starting address of the whole group
	private GroupSubrecord[] group;

	public OmfGroupRecord(BinaryReader reader) throws IOException {
		super(reader);
	}

	@Override
	public void parseData() throws IOException, OmfException {
		groupNameIndex = OmfUtils.readIndex(dataReader);
		ArrayList<GroupSubrecord> grouplist = new ArrayList<>();
		while (dataReader.getPointerIndex() < dataEnd) {
			GroupSubrecord subrec = GroupSubrecord.read(dataReader);
			grouplist.add(subrec);
		}
		group = new GroupSubrecord[grouplist.size()];
		grouplist.toArray(group);
	}

	public String getName() {
		return groupName;
	}

	public void setStartAddress(long val) {
		vma = val;
	}

	public long getStartAddress() {
		return vma;
	}

	/**
	 * This is the segment selector needed for this object
	 * @return The segment selector
	 */
	public int getFrameDatum() {
		return 0;				// TODO:  Need to fill in a real segment selector
	}

	public int numSegments() {
		return group.length;
	}

	public byte getSegmentComponentType(int i) {
		return group[i].componentType;
	}

	public int getSegmentIndex(int i) {
		return group[i].segmentIndex.value();
	}

	public Address getAddress(Language language) {
		AddressSpace addrSpace = language.getDefaultSpace();
		return addrSpace.getAddress(vma);
	}

	public void resolveNames(List<String> nameList) throws OmfException {
		if (groupNameIndex.value() <= 0) {
			throw new OmfException("Cannot have unused group name");
		}
		if (groupNameIndex.value() > nameList.size()) {
			throw new OmfException("Group name index out of bounds");
		}
		groupName = nameList.get(groupNameIndex.value() - 1);
	}

	public static class GroupSubrecord {
		private byte componentType;
		private OmfIndex segmentIndex;

		public static GroupSubrecord read(BinaryReader reader) throws IOException {
			GroupSubrecord subrec = new GroupSubrecord();
			subrec.componentType = reader.readNextByte();
			subrec.segmentIndex = OmfUtils.readIndex(reader);
			return subrec;
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return OmfUtils.toOmfRecordDataType(this, OmfRecordTypes.getName(recordType));
	}
}
