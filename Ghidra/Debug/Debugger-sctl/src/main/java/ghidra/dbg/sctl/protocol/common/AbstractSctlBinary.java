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
package ghidra.dbg.sctl.protocol.common;

import java.util.List;

import ghidra.comm.packet.Packet;

public abstract class AbstractSctlBinary extends Packet {
	public abstract void setNamespaceID(long nsid);

	public abstract long getNamespaceID();

	public abstract void setPath(String path);

	public abstract String getPath();

	public abstract void setExecutable(boolean isexe);

	public abstract boolean isExecutable();

	public abstract boolean supportsBase();

	public abstract void setBase(long base);

	public abstract long getBase();

	public abstract boolean supportsSections();

	public abstract AbstractSctlSection addSection();

	public abstract List<? extends AbstractSctlSection> getSections();
}
