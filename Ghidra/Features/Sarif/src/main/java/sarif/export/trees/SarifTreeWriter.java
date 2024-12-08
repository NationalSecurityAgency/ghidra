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
package sarif.export.trees;

import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.List;

import generic.stl.Pair;
import ghidra.program.model.listing.ProgramModule;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import sarif.export.AbstractExtWriter;
import sarif.export.SarifObject;
import sarif.managers.ProgramTreeSarifMgr;

public class SarifTreeWriter extends AbstractExtWriter {

	private List<Pair<String, ProgramModule>> modules;
	private List<Object> visited = new ArrayList<>();

	public SarifTreeWriter(List<Pair<String, ProgramModule>> target, Writer baseWriter) throws IOException {
		super(baseWriter);
		this.modules = target;
	}

	@Override
	protected void genRoot(TaskMonitor monitor) throws CancelledException, IOException {
		genTree(monitor);
		root.add("trees", objects);
	}

	private void genTree(TaskMonitor monitor) throws CancelledException, IOException {
		monitor.initialize(modules.size());
		for (Pair<String, ProgramModule> pair : modules) {
			ExtModule isf = new ExtModule(pair.first, pair.second, visited);
			SarifObject sarif = new SarifObject(ProgramTreeSarifMgr.SUBKEY, ProgramTreeSarifMgr.KEY, getTree(isf), null);
			objects.add(getTree(sarif));
			monitor.increment();
		}
	}

}
