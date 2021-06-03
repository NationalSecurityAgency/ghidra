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
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.Validate;

import ghidra.app.util.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.classfinder.ExtensionPoint;
import ghidra.util.task.TaskMonitor;

/**
 * The interface that all exporters must implement.
 */
abstract public class Exporter implements ExtensionPoint {
	protected final static List<Option> EMPTY_OPTIONS = new ArrayList<>();

	protected MessageLog log = new MessageLog();
	protected ServiceProvider provider;

	private String name;
	private String extension;
	private HelpLocation help;

	/**
	 * Constructs a new exporter.
	 * @param name       the display name of this exporter
	 * @param extension  the default extension for this exporter
	 * @param help       the help location for this exporter
	 */
	protected Exporter(String name, String extension, HelpLocation help) {
		this.name = Validate.notNull(name);
		this.extension = Validate.notNull(extension);
		this.help = help;
	}

	/**
	 * Returns the display name of this exporter.
	 * @return the display name of this exporter
	 */
	final public String getName() {
		return name;
	}

	/**
	 * Returns the default extension for this exporter.
	 * For example, .html for .xml.
	 * @return the default extension for this exporter
	 */
	final public String getDefaultFileExtension() {
		return extension;
	}

	/**
	 * Returns the help location for this exporter.
	 * It should return null only if no help documentation exists.
	 * @return the help location for this exporter
	 */
	final public HelpLocation getHelpLocation() {
		return help;
	}

	/**
	 * Returns the message log the may have been created during an export.
	 * The message log is used to log warnings and other non-critical messages.
	 * @return the message log
	 */
	final public MessageLog getMessageLog() {
		return log;
	}

	/**
	 * Sets the exporter service provider.
	 * @param provider the exporter service provider
	 */
	final public void setExporterServiceProvider(ServiceProvider provider) {
		this.provider = provider;
	}

	/**
	 * Returns true if this exporter knows how to export the given domain object.  For example,
	 * some exporters know how to export programs, other exporters can export project data type
	 * archives.
	 * @param domainObjectClass the class of the domain object to test for exporting.
	 * @return true if this exporter knows how to export the given domain object.
	 */
	public boolean canExportDomainObject(Class<? extends DomainObject> domainObjectClass) {
		return Program.class.isAssignableFrom(domainObjectClass);
	}

	/**
	 * Returns true if this exporter can export less than the entire domain file.
	 * @return true if this exporter can export less than the entire domain file.
	 */
	public boolean supportsPartialExport() {
		return true;
	}

	/**
	 * Returns the available options for this exporter.
	 * The program is needed because some exporters
	 * may have options that vary depending on the specific
	 * program being exported.
	 * @param domainObjectService a service for retrieving the applicable domainObject.
	 * @return the available options for this exporter
	 */
	abstract public List<Option> getOptions(DomainObjectService domainObjectService);

	/**
	 * Sets the options. This method is not for defining the options, but
	 * rather it is for setting the values of options. If invalid options
	 * are passed in, then OptionException should be thrown.
	 * @param options the option values for this exporter
	 * @throws OptionException if invalid options are passed in
	 */
	abstract public void setOptions(List<Option> options) throws OptionException;

	/**
	 * Actually does the work of exporting the program.
	 *
	 * @param file        the output file to write the exported info
	 * @param domainObj   the domain object to export
	 * @param addrSet     the address set if only a portion of the program should be exported
	 * @param monitor     the task monitor
	 *
	 * @return true if the program was successfully exported; otherwise, false.  If the program
	 *   was not successfully exported, the message log should be checked to find the source of
	 *   the error.
	 *
	 * @throws ExporterException
	 * @throws IOException
	 */
	abstract public boolean export(File file, DomainObject domainObj, AddressSetView addrSet,
			TaskMonitor monitor) throws ExporterException, IOException;

	@Override
	final public String toString() {
		return getName();
	}

}
