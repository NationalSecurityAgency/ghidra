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
package sarif.export.extlib;

import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonArray;

import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalLocationIterator;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import sarif.export.AbstractExtWriter;
import sarif.export.SarifObject;
import sarif.managers.ExternalLibSarifMgr;

public class SarifExternalLibraryWriter extends AbstractExtWriter {

	private List<String> externalNames = new ArrayList<>();
	private ExternalManager externalManager;

	public SarifExternalLibraryWriter(ExternalManager externalManager, List<String> request, Writer baseWriter)
			throws IOException {
		super(baseWriter);
		this.externalManager = externalManager;
		this.externalNames = request;
	}

	@Override
	protected void genRoot(TaskMonitor monitor) throws CancelledException, IOException {
		genLibraries(monitor);
		root.add("definedData", objects);
	}

	private void genLibraries(TaskMonitor monitor) throws CancelledException, IOException {
		monitor.initialize(externalNames.size());
		for (String n : externalNames) {
			String path = externalManager.getExternalLibraryPath(n);
			if (path == null) {
				path = "";
			}
			ExtLibrary lib = new ExtLibrary(n, path, SourceType.DEFAULT);
			SarifObject sarif = new SarifObject(ExternalLibSarifMgr.SUBKEY0, ExternalLibSarifMgr.KEY, getTree(lib), null);
			objects.add(getTree(sarif));
			
			ExternalLocationIterator externalLocations = externalManager.getExternalLocations(n);
			while (externalLocations.hasNext()) {
				ExternalLocation loc = externalLocations.next();
				ExtLibraryLocation obj = new ExtLibraryLocation(loc);
				SarifObject sarif2 = new SarifObject(ExternalLibSarifMgr.SUBKEY1, ExternalLibSarifMgr.KEY, getTree(obj), loc.getAddress(), loc.getAddress());
				objects.add(getTree(sarif2));
			}
			monitor.increment();
		}
	}

	public JsonArray getResults() {
		return objects;
	}

}
