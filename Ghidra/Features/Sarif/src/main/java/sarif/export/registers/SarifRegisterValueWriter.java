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
package sarif.export.registers;

import java.io.IOException;
import java.io.Writer;
import java.math.BigInteger;
import java.util.List;

import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ProgramContext;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import sarif.export.AbstractExtWriter;
import sarif.export.SarifObject;
import sarif.managers.RegisterValuesSarifMgr;

public class SarifRegisterValueWriter extends AbstractExtWriter {

	List<AddressRange> ranges;
	ProgramContext context;
	List<Register> registers;

	public SarifRegisterValueWriter(ProgramContext context, List<Register> registers, List<AddressRange> request,
			Writer baseWriter) throws IOException {
		super(baseWriter);
		this.ranges = request;
		this.context = context;
		this.registers = registers;
	}

	@Override
	protected void genRoot(TaskMonitor monitor) throws CancelledException, IOException {
		genRegisters(monitor);
		root.add("registers", objects);
	}

	private void genRegisters(TaskMonitor monitor) throws CancelledException, IOException {
		monitor.initialize(ranges.size());
		for (AddressRange r : ranges) {
			for (Register reg : registers) {
				AddressRangeIterator it = context.getRegisterValueAddressRanges(reg, r.getMinAddress(),
						r.getMaxAddress());
				while (it.hasNext()) {
					monitor.checkCancelled();
					AddressRange valueRange = it.next();
					BigInteger value = context.getValue(reg, valueRange.getMinAddress(), false);
					if (value == null) {
						continue;
					}
					ExtRegisterValue isf = new ExtRegisterValue(reg, value.toString(16));
					SarifObject sarif = new SarifObject(RegisterValuesSarifMgr.SUBKEY, RegisterValuesSarifMgr.KEY, getTree(isf), valueRange.getMinAddress(), valueRange.getMaxAddress());
					objects.add(getTree(sarif));
				}
			}
			monitor.increment();
		}
	}

}
