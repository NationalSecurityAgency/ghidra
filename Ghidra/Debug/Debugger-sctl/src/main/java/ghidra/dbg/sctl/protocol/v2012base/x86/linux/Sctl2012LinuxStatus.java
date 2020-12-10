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

import java.util.ArrayList;
import java.util.List;

import ghidra.comm.packet.annot.CountedByField;
import ghidra.comm.packet.annot.RepeatedField;
import ghidra.comm.packet.fields.PacketField;
import ghidra.dbg.sctl.protocol.common.AbstractSctlStatus;

/**
 * The format of {@code stat[]} in SCTL's Linux dialects
 */
public class Sctl2012LinuxStatus extends AbstractSctlStatus {
	@Override
	public boolean supportsProcessID() {
		return true;
	}

	@Override
	public void setProcessID(long pid) {
		this.pid = pid;
	}

	@Override
	public long getProcessID() {
		return pid;
	}

	@Override
	public Sctl2012LinuxRegion addRegion() {
		Sctl2012LinuxRegion r = new Sctl2012LinuxRegion();
		regions.add(r);
		return r;
	}

	@Override
	public List<Sctl2012LinuxRegion> getRegions() {
		return regions;
	}

	@Override
	public Sctl2012LinuxBinary addBinary() {
		Sctl2012LinuxBinary b = new Sctl2012LinuxBinary();
		bins.add(b);
		return b;
	}

	@Override
	public List<Sctl2012LinuxBinary> getBinaries() {
		return bins;
	}

	@PacketField
	public long pid;

	@PacketField
	public long nr;

	@PacketField
	@RepeatedField
	@CountedByField("nr")
	public List<Sctl2012LinuxRegion> regions = new ArrayList<>();

	@PacketField
	public long nb;

	@PacketField
	@RepeatedField
	@CountedByField("nb")
	public List<Sctl2012LinuxBinary> bins = new ArrayList<>();
}
