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
package sarif.export.code;

import java.io.IOException;
import java.io.Writer;
import java.util.List;

import generic.stl.Pair;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import sarif.export.AbstractExtWriter;
import sarif.export.SarifObject;
import sarif.managers.CodeSarifMgr;

public class SarifCodeWriter extends AbstractExtWriter {
	
	private List<AddressRange> blocks;
	private List<Pair<Instruction, FlowOverride>> overrides;

	public SarifCodeWriter(List<AddressRange> target0, List<Pair<Instruction, FlowOverride>> target1, Writer baseWriter) throws IOException {
		super(baseWriter);
		this.blocks = target0;
		this.overrides = target1;
	}

	@Override
	protected void genRoot(TaskMonitor monitor) throws CancelledException, IOException {
		genCode(monitor);
		genOverrides(monitor);
		root.add("code", objects);
	}

	private void genCode(TaskMonitor monitor) throws CancelledException, IOException{
		monitor.initialize(blocks.size());
		for (AddressRange range : blocks) {
			ExtCodeBlock isf = new ExtCodeBlock(range);
			SarifObject sarif = new SarifObject(CodeSarifMgr.SUBKEY, CodeSarifMgr.KEY, getTree(isf), range.getMinAddress(), range.getMaxAddress());
			objects.add(getTree(sarif));
			monitor.increment();
		}
	}

	private void genOverrides(TaskMonitor monitor) throws CancelledException, IOException{
		monitor.initialize(overrides.size());
		for (Pair<Instruction, FlowOverride> pair : overrides) {
			Instruction inst = pair.first;
			ExtCodeOverride isf = new ExtCodeOverride(pair);
			SarifObject sarif = new SarifObject(CodeSarifMgr.SUBKEY2, CodeSarifMgr.KEY, getTree(isf), inst.getMinAddress(), inst.getMaxAddress());
			objects.add(getTree(sarif));
			monitor.increment();
		}
	}
}
