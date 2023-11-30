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
package sarif.export.props;

import java.io.IOException;
import java.io.Writer;
import java.util.Collections;
import java.util.List;

import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import sarif.export.AbstractExtWriter;
import sarif.export.SarifObject;
import sarif.managers.PropertiesSarifMgr;

public class SarifPropertyListWriter extends AbstractExtWriter {

	Program program;
	List<String> options;

	public SarifPropertyListWriter(Program program, List<String> request, Writer baseWriter) throws IOException {
		super(baseWriter);
		this.program = program;
		this.options = request;
	}

	@Override
	protected void genRoot(TaskMonitor monitor) throws CancelledException, IOException {
		genList(monitor);
		root.add("properties", objects);
	}

	private void genList(TaskMonitor monitor) throws CancelledException, IOException {
		monitor.initialize(options.size());
		for (String listName : options) {
			Options propList = program.getOptions(listName);
			List<String> propNames = propList.getOptionNames();
			Collections.sort(propNames);
			for (String name : propNames) {
				if (monitor.isCancelled()) {
					throw new CancelledException();
				}
				if (propList.isAlias(name)) { // don't write out properties that are just mirrors of some other property
					continue;
				}
				if (propList.isDefaultValue(name)) { // don't write out default properties.
					continue;
				}
				String keyName =  listName + Options.DELIMITER_STRING + name;
				ExtProperty isf = new ExtProperty(keyName, propList);
				SarifObject sarif = new SarifObject(PropertiesSarifMgr.SUBKEY, PropertiesSarifMgr.KEY, getTree(isf), null);
				objects.add(getTree(sarif));
			}
		}
	}

}
