/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.util.bin.format.macos.cfm;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class CFragResource implements StructConverter {
	private int   reservedA;
	private int   reservedB;
	private int   version;
	private int   reservedC;
	private int   reservedD;
	private int   reservedE;
	private int   reservedF;
	private int   memberCount;

	private List<CFragResourceMember> _members = new ArrayList<CFragResourceMember>();

	public CFragResource(BinaryReader reader) throws IOException {
		reservedA    = reader.readNextInt();
		reservedB    = reader.readNextInt();
		version      = reader.readNextInt();
		reservedD    = reader.readNextInt();
		reservedE    = reader.readNextInt();
		reservedF    = reader.readNextInt();
		reservedC    = reader.readNextInt();
		memberCount  = reader.readNextInt();

		if (reservedA != 0 ||
			reservedB != 0 ||
			reservedC != 0 ||
			reservedD != 0 ||
			reservedE != 0 ||
			reservedF != 0) {
			throw new IOException("Reserved fields contain invalid value(s).");
		}

		for (int i = 0 ; i < memberCount ; ++i) {
			long oldIndex = reader.getPointerIndex();
			CFragResourceMember member = new CFragResourceMember(reader);
			_members.add(member);
			reader.setPointerIndex(oldIndex + member.getMemberSize());
		}
	}

	public int getVersion() {
		return version;
	}

	public int getMemberCount() {
		return memberCount;
	}

	public List<CFragResourceMember> getMembers() {
		return _members;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(CFragResource.class);
	}
}
