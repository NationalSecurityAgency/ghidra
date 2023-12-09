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
package sarif.export.ep;

import java.io.IOException;
import java.io.Writer;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import sarif.export.AbstractExtWriter;
import sarif.export.SarifObject;
import sarif.managers.ExtEntryPointSarifMgr;

public class SarifEntryPointWriter extends AbstractExtWriter {
	
	private List<Address> entryPoints;

	public SarifEntryPointWriter(List<Address> request, Writer baseWriter) throws IOException {
		super(baseWriter);
		this.entryPoints = request;
	}

	@Override
	protected void genRoot(TaskMonitor monitor) throws CancelledException, IOException {
		genCode(monitor);
		root.add("entryPoints", objects);
	}

	private void genCode(TaskMonitor monitor) throws CancelledException, IOException{
		monitor.initialize(entryPoints.size());
		for (Address addr : entryPoints) {
			ExtEntryPoint isf = new ExtEntryPoint(addr);
			SarifObject sarif = new SarifObject(ExtEntryPointSarifMgr.SUBKEY, ExtEntryPointSarifMgr.KEY, getTree(isf), addr, addr);
			objects.add(getTree(sarif));
			monitor.increment();
		}
	}

}
