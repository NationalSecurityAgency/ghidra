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

import ghidra.app.util.DomainObjectService;
import ghidra.app.util.Option;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.DataTypeArchiveDB;
import ghidra.program.model.address.AddressSetView;
import ghidra.util.HelpLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class GdtExporter extends Exporter {

	public static final String EXTENSION = "gdt";
	public static final String SUFFIX = "." + EXTENSION;

	public static final String NAME = "Ghidra Data Type Archive File";

	public GdtExporter() {
		super(NAME, EXTENSION, new HelpLocation("ExporterPlugin", EXTENSION));
	}

	@Override
	public boolean canExportDomainObject(Class<? extends DomainObject> domainObjectClass) {
		return DataTypeArchiveDB.class.isAssignableFrom(domainObjectClass);
	}

	@Override
	public boolean canExportDomainFile(DomainFile domainFile) {
		return canExportDomainObject(domainFile.getDomainObjectClass());
	}

	@Override
	public boolean equals(Object obj) {
		return (obj instanceof GdtExporter);
	}

	@Override
	public boolean export(File file, DomainObject domainObj, AddressSetView addrSet,
			TaskMonitor monitor) {
		try {
			file.delete();
			domainObj.saveToPackedFile(file, monitor);
		}
		catch (UnsupportedOperationException e) {
			log.appendMsg("Content does not support packed file export!");
			log.appendException(e);
			return false;
		}
		catch (CancelledException ce) {
			return false;
		}
		catch (Exception e) {
			log.appendMsg("Unexpected exception exporting file: " + e.getMessage());
			return false;
		}
		return true;
	}

	@Override
	public boolean export(File file, DomainFile domainFile, TaskMonitor monitor)
			throws ExporterException, IOException {
		if (!canExportDomainFile(domainFile)) {
			throw new UnsupportedOperationException("only DataTypeArchiveDB files are supported");
		}
		try {
			domainFile.packFile(file, monitor);
		}
		catch (CancelledException e) {
			return false;
		}
		catch (Exception e) {
			log.appendMsg("Unexpected exception exporting file: " + e.getMessage());
			return false;
		}
		return true;
	}

	@Override
	public List<Option> getOptions(DomainObjectService domainObjectService) {
		return EMPTY_OPTIONS;
	}

	@Override
	public void setOptions(List<Option> options) {
		// no options for this exporter
	}

	/**
	 * Returns false.  GDT export only supports entire database.
	 */
	@Override
	public boolean supportsAddressRestrictedExport() {
		return false;
	}
}
