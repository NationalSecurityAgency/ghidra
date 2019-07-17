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
import ghidra.app.util.xml.ProgramXmlMgr;
import ghidra.app.util.xml.XmlProgramOptions;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * An implementation of exporter that creates
 * an XML representation of the program.
 */
public class XmlExporter extends Exporter {
	private XmlProgramOptions options = new XmlProgramOptions();

	/**
	 * Constructs a new XML exporter.
	 */
	public XmlExporter() {
		super("XML", "xml", new HelpLocation("ExporterPlugin", "xml"));
	}

	@Override
	public List<Option> getOptions(DomainObjectService domainObjectService) {
		if (options == null) {
			options = new XmlProgramOptions();
		}
		return options.getOptions(false);
	}

	@Override
	public void setOptions(List<Option> options) throws OptionException {
		this.options.setOptions(options);
	}

	@Override
	public boolean export(File file, DomainObject domainObj, AddressSetView addrSet, TaskMonitor monitor)
			throws IOException, ExporterException {

		log.clear();

		if (!(domainObj instanceof Program)) {
			log.appendMsg("Unsupported type: "+domainObj.getClass().getName());
			return false;
		}
		Program program = (Program)domainObj;

		if (addrSet == null) {
			addrSet = program.getMemory();
		}

		ProgramXmlMgr mgr = new ProgramXmlMgr(file);

		try {
			log = mgr.write(program, addrSet, monitor, options);
		}
		catch (CancelledException e) {
			throw new ExporterException("User cancelled XML export.");
		}

		options = null;

		return true;
	}
}
