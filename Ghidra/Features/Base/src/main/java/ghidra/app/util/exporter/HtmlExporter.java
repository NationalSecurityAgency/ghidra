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
package ghidra.app.util.exporter;

import java.io.File;
import java.io.IOException;
import java.util.List;

import ghidra.app.util.*;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.task.TaskMonitor;

/**
 * An implementation of exporter that creates
 * an HTML representation of the program.
 */
public class HtmlExporter extends Exporter {
	private ProgramTextOptions options;

	/**
	 * Constructs a new HTML exporter.
	 */
	public HtmlExporter() {
		super("HTML", "html", new HelpLocation("ExporterPlugin", "html"));
	}

	@Override
	public List<Option> getOptions(DomainObjectService domainObjectService) {
		if (options == null) {
			options = new ProgramTextOptions();
			options.setHTML(true);
		}
		return options.getOptions();
	}

	@Override
	public void setOptions(List<Option> options) throws OptionException {
		this.options.setOptions(options);
	}

	@Override
	public boolean export(File file, DomainObject domainObj, AddressSetView addressSet,
			TaskMonitor monitor) throws IOException, ExporterException {

		if (!(domainObj instanceof Program)) {
			log.appendMsg("Unsupported type: " + domainObj.getClass().getName());
			return false;
		}
		Program program = (Program) domainObj;

		getOptions(() -> program);
		new ProgramTextWriter(file, program, addressSet, monitor, options, provider);
		return true;
	}
}
