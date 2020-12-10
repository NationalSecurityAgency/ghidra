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
import ghidra.dbg.sctl.protocol.common.AbstractSctlStatus;

public class Sctl2018Status extends AbstractSctlStatus {
	@Override
	public boolean supportsProcessID() {
		return false;
	}

	@Override
	public void setProcessID(long pid) {
		throw new UnsupportedOperationException();
	}

	@Override
	public long getProcessID() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Sctl2018Region addRegion() {
		Sctl2018Region r = new Sctl2018Region();
		regions.add(r);
		return r;
	}

	@Override
	public List<Sctl2018Region> getRegions() {
		return regions;
	}

	@Override
	public Sctl2018Binary addBinary() {
		Sctl2018Binary b = new Sctl2018Binary();
		bins.add(b);
		return b;
	}

	@Override
	public List<Sctl2018Binary> getBinaries() {
		return bins;
	}

	@PacketField
	public long nr;

	@PacketField
	@RepeatedField
	@CountedByField("nr")
	public List<Sctl2018Region> regions = new ArrayList<>();

	@PacketField
	public long nb;

	@PacketField
	@RepeatedField
	@CountedByField("nb")
	public List<Sctl2018Binary> bins = new ArrayList<>();
}
