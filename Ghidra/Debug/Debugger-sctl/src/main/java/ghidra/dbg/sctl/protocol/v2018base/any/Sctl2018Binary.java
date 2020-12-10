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
package ghidra.dbg.sctl.protocol.v2018base.any;

import java.util.ArrayList;
import java.util.List;

import ghidra.comm.packet.annot.CountedByField;
import ghidra.comm.packet.annot.RepeatedField;
import ghidra.comm.packet.fields.PacketField;
import ghidra.dbg.sctl.protocol.common.AbstractSctlBinary;
import ghidra.dbg.sctl.protocol.common.SctlString;

public class Sctl2018Binary extends AbstractSctlBinary {
	@Override
	public void setNamespaceID(long nsid) {
		this.nsid = nsid;
	}

	@Override
	public long getNamespaceID() {
		return nsid;
	}

	@Override
	public void setPath(String path) {
		this.path = new SctlString(path);
	}

	@Override
	public String getPath() {
		return path.str;
	}

	@Override
	public void setExecutable(boolean isexe) {
		this.isexe = isexe;
	}

	@Override
	public boolean isExecutable() {
		return isexe;
	}

	@Override
	public boolean supportsBase() {
		return false;
	}

	@Override
	public void setBase(long base) {
		throw new UnsupportedOperationException();
	}

	@Override
	public long getBase() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean supportsSections() {
		return true;
	}

	@Override
	public Sctl2018Section addSection() {
		Sctl2018Section s = new Sctl2018Section();
		sections.add(s);
		return s;
	}

	@Override
	public List<Sctl2018Section> getSections() {
		return sections;
	}

	@PacketField
	public long nsid;

	@PacketField
	public boolean isexe;

	@PacketField
	public SctlString path;

	@PacketField
	public long ns;

	@PacketField
	@RepeatedField
	@CountedByField("ns")
	public List<Sctl2018Section> sections = new ArrayList<>();
}
