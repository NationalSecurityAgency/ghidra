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
package sarif.export.ref;

import java.io.IOException;
import java.io.Writer;
import java.util.Iterator;

import com.google.gson.JsonArray;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateReference;
import ghidra.program.model.symbol.EquateTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import sarif.export.AbstractExtWriter;
import sarif.export.SarifObject;

public class SarifEquateWriter extends AbstractExtWriter {
	
	private AddressSetView set;
	private EquateTable equateTable;

	public SarifEquateWriter(EquateTable equateTable, AddressSetView set, Writer baseWriter) throws IOException {
		super(baseWriter);
		this.equateTable = equateTable;
		this.set = set;
	}

	@Override
	protected void genRoot(TaskMonitor monitor) throws CancelledException, IOException {
		genReferences(monitor);
		root.add("equates", objects);
	}

	private void genReferences(TaskMonitor monitor) throws CancelledException, IOException{

		Iterator<Equate> iter = equateTable.getEquates();
		while (iter.hasNext()) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			Equate equate = iter.next();
			String name = equate.getName();
			long value = equate.getValue();
			EquateReference[] refs = equate.getReferences();
			for (int i = 0; i < refs.length; i++) {
				if (monitor.isCancelled()) {
					return;
				}
				Address addr = refs[i].getAddress();
				if (!set.contains(addr)) {
					continue;
				}
				ExtEquateReference eref = new ExtEquateReference(refs[i], name, value);
				SarifObject sarif = new SarifObject("Ref.Equate", "REFERENCES", getTree(eref), addr, addr);
				objects.add(getTree(sarif));
			}
		}
	}
	
	public JsonArray getResults() {
		return objects;
	}

}
