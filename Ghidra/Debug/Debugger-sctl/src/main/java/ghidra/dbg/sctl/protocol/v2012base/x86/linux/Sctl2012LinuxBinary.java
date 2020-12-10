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
package ghidra.dbg.sctl.protocol.v2012base.x86.linux;

import java.util.List;

import ghidra.comm.packet.fields.PacketField;
import ghidra.dbg.sctl.protocol.common.*;

/**
 * Format of SCTL's {@code bin} for Linux dialects
 */
public class Sctl2012LinuxBinary extends AbstractSctlBinary {
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
		return true;
	}

	@Override
	public void setBase(long base) {
		this.base = base;
	}

	@Override
	public long getBase() {
		return base;
	}

	@Override
	public boolean supportsSections() {
		return false;
	}

	@Override
	public AbstractSctlSection addSection() {
		throw new UnsupportedOperationException();
	}

	@Override
	public List<? extends AbstractSctlSection> getSections() {
		throw new UnsupportedOperationException();
	}

	@PacketField
	public long nsid;

	@PacketField
	public long base;

	@PacketField
	public boolean isexe;

	@PacketField
	public SctlString path;
}
