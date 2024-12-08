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
package sarif.export.dd;

import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.listing.Data;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import sarif.export.AbstractExtWriter;
import sarif.export.SarifObject;
import sarif.managers.DefinedDataSarifMgr;

public class SarifDataWriter extends AbstractExtWriter {
	
	private List<Data> definedData = new ArrayList<>();

	public SarifDataWriter(List<Data> target, Writer baseWriter) throws IOException {
		super(baseWriter);
		this.definedData = target;
	}

	@Override
	protected void genRoot(TaskMonitor monitor) throws CancelledException, IOException {
		genData(monitor);
		root.add("definedData", objects);
	}

	private void genData(TaskMonitor monitor) throws CancelledException, IOException{
		monitor.initialize(definedData.size());
		for (Data d : definedData) {
			ExtData isf = new ExtData(d);
			SarifObject sarif = new SarifObject("DefinedData", DefinedDataSarifMgr.KEY, getTree(isf), d.getMinAddress(), d.getMaxAddress());
			objects.add(getTree(sarif));
			monitor.increment();
		}
	}
	
}
