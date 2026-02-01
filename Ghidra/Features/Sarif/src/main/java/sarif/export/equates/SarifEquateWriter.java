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
package sarif.export.equates;

import java.io.IOException;
import java.io.Writer;
import java.util.List;

import ghidra.program.model.symbol.Equate;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import sarif.export.AbstractExtWriter;
import sarif.export.SarifObject;
import sarif.managers.EquatesSarifMgr;

public class SarifEquateWriter extends AbstractExtWriter {
	
	private List<Equate> equates;

	public SarifEquateWriter(List<Equate> request, Writer baseWriter) throws IOException {
		super(baseWriter);
		this.equates = request;
	}

	@Override
	protected void genRoot(TaskMonitor monitor) throws CancelledException, IOException {
		genCode(monitor);
		root.add("equates", objects);
	}

	private void genCode(TaskMonitor monitor) throws CancelledException, IOException{
		monitor.initialize(equates.size());
		for (Equate equate : equates) {
			ExtEquate isf = new ExtEquate(equate);
			SarifObject sarif = new SarifObject(EquatesSarifMgr.SUBKEY, EquatesSarifMgr.KEY, getTree(isf), null);
			objects.add(getTree(sarif));
			monitor.increment();
		}
	}

}
