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
package sarif.export.relocs;

import java.io.IOException;
import java.io.Writer;
import java.util.List;

import ghidra.program.model.reloc.Relocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import sarif.export.AbstractExtWriter;
import sarif.export.SarifObject;
import sarif.managers.RelocationTableSarifMgr;

public class SarifRelocationWriter extends AbstractExtWriter {

	List<Relocation> relocs;

	public SarifRelocationWriter(List<Relocation> request, Writer baseWriter) throws IOException {
		super(baseWriter);
		this.relocs = request;
	}

	@Override
	protected void genRoot(TaskMonitor monitor) throws CancelledException, IOException {
		genRelocation(monitor);
		root.add("relocations", objects);
	}

	private void genRelocation(TaskMonitor monitor) throws CancelledException, IOException {
		monitor.initialize(relocs.size());
		for (Relocation r : relocs) {
			ExtRelocation isf = new ExtRelocation(r);
			SarifObject sarif = new SarifObject(RelocationTableSarifMgr.SUBKEY, RelocationTableSarifMgr.KEY,
					getTree(isf), r.getAddress(), r.getAddress());
			objects.add(getTree(sarif));
			monitor.increment();
		}
	}

}
