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
package ghidra.lisa.gui;

import java.io.IOException;

import ghidra.lisa.pcode.locations.InstLocation;
import ghidra.lisa.pcode.locations.PcodeLocation;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import it.unive.lisa.program.cfg.statement.Statement;
import sarif.export.*;

public class SarifLogicalLocationWriter extends AbstractExtWriter {

	private PcodeLocation location;

	private WrappedLogicalLocation lloc;

	public SarifLogicalLocationWriter(String key, Function f, Statement statement)
			throws IOException {
		super(null);
		Address addr;
		String loc, op;
		if (statement.getLocation() instanceof PcodeLocation ploc) {
			this.location = ploc;
			SequenceNumber seqnum = location.op.getSeqnum();
			String seq = seqnum.getTarget() + ":" + seqnum.getTime();
			loc = f.getName();
			loc += "@" + f.getEntryPoint();
			loc += ":" + seq;
			addr = location.getAddress();
			op = seq + " " + location.op.toString();
		}
		else {
			loc = f.getName();
			InstLocation instLoc = (InstLocation) statement.getLocation();
			addr = instLoc.getAddress();
			loc += "@" + addr;
			op = instLoc.toString();
		}
		ExtLogicalLocation ext = new ExtLogicalLocation(key, f, loc, op);
		lloc = new WrappedLogicalLocation(ext, addr);
	}

	@Override
	protected void genRoot(TaskMonitor monitor) throws CancelledException, IOException {
		genData(monitor);
		root.add("logicalLocation", objects);
	}

	private void genData(TaskMonitor monitor) {
		objects.add(getTree(lloc.getLogicalLocation()));
	}

	public WrappedLogicalLocation getLogicalLocation() {
		return lloc;
	}

}
