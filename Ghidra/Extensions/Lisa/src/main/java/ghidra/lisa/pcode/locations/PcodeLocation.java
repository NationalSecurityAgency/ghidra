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
package ghidra.lisa.pcode.locations;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;
import it.unive.lisa.program.cfg.CodeLocation;

public class PcodeLocation implements CodeLocation {

	public PcodeOp op;

	public PcodeLocation(PcodeOp op) {
		this.op = op;
	}

	@Override
	public int compareTo(CodeLocation o) {
		if (o instanceof PcodeLocation pl) {
			return op.getSeqnum().compareTo(pl.op.getSeqnum());
		}
		return -1;
	}

	@Override
	public String getCodeLocation() {
		return op.getSeqnum().toString();
	}

	public int getOpcode() {
		return op.getOpcode();
	}

	public Address getAddress() {
		return op.getSeqnum().getTarget();
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof PcodeLocation ploc) {
			return this.op.getSeqnum().equals(ploc.op.getSeqnum());
		}
		return false;
	}

	@Override
	public int hashCode() {
		return op.getSeqnum().hashCode();
	}

	@Override
	public String toString() {
		return getCodeLocation();
	}
}
