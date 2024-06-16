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
import ghidra.framework.model.DomainFile;
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
	 * Returns true if this exporter is capable of exporting the given domain file/object content
	 * type.  For example, some exporters have the ability to export programs, other exporters can 
	 * export project data type archives.
	 * <p>
	 * NOTE: This method should only be used as a preliminary check, if neccessary, to identify 
	 * exporter implementations that are capable of handling a specified content type/class.  Prior
	 * to export a final check should be performed based on the export or either a 
	 * {@link DomainFile} or {@link DomainObject}:
	 * <p>
	 * {@link DomainFile} export - the method {@link #canExportDomainFile(DomainFile)} should be 
	 * used to verify a direct project file export is possible using the 
	 * {@link #export(File, DomainFile, TaskMonitor)} method.
	 * <p>
	 * {@link DomainObject} export - the method {@link #canExportDomainObject(DomainObject)} should 
	 * be used to verify an export of a specific object is possible using the 
	 * {@link #export(File, DomainObject, AddressSetView, TaskMonitor)} method.
	 * 
	 * avoid opening DomainFile when possible.
	 * @param domainObjectClass the class of the domain object to test for exporting.
	 * @return true if this exporter knows how to export the given domain object type.
	 */
	public boolean canExportDomainObject(Class<? extends DomainObject> domainObjectClass) {
		return Program.class.isAssignableFrom(domainObjectClass);
	}

	/**
	 * Returns true if exporter can export the specified {@link DomainFile} without instantiating 
	 * a {@link DomainObject}.  This method should be used prior to exporting using the
	 * {@link #export(File, DomainFile, TaskMonitor)} method.  All exporter capable of a 
	 * {@link DomainFile} export must also support a export of a {@link DomainObject} so that any
	 * possible data modification/upgrade is included within resulting export.
	 * 
	 * @param domainFile domain file
	 * @return true if export can occur else false if not
	 */
	public boolean canExportDomainFile(DomainFile domainFile) {
		return false;
	}

	/**
	 * Returns true if this exporter knows how to export the given domain object considering any
	 * constraints based on the specific makeup of the object.  This method should be used prior to
	 * exporting using the {@link #export(File, DomainObject, AddressSetView, TaskMonitor)} method.
	 * 
	 * @param domainObject the domain object to test for exporting.
	 * @return true if this exporter knows how to export the given domain object.
	 */
	public boolean canExportDomainObject(DomainObject domainObject) {
		if (domainObject == null) {
			return false;
		}
		return canExportDomainObject(domainObject.getClass());
	}

	/**
	 * Returns true if this exporter can perform a restricted export of a {@link DomainObject}
	 * based upon a specified {@link AddressSetView}.
	 * 
	 * @return true if this exporter can export less than the entire domain file.
	 */
	public boolean supportsAddressRestrictedExport() {
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
	 * Actually does the work of exporting a {@link DomainObject}.  Export will include all 
	 * saved and unsaved modifications which may have been made to the object.
	 *
	 * @param file        the output file to write the exported info
	 * @param domainObj   the domain object to export
	 * @param addrSet     the address set if only a portion of the program should be exported
	 *                    NOTE: see {@link #supportsAddressRestrictedExport()}.
	 * @param monitor     the task monitor
	 *
	 * @return true if the program was successfully exported; otherwise, false.  If the program
	 *   was not successfully exported, the message log should be checked to find the source of
	 *   the error.
	 *
	 * @throws ExporterException if export error occurs
	 * @throws IOException if an IO error occurs
	 */
	abstract public boolean export(File file, DomainObject domainObj, AddressSetView addrSet,
			TaskMonitor monitor) throws ExporterException, IOException;

	/**
	 * Actually does the work of exporting a domain file, if supported (see
	 * {@link #canExportDomainFile(DomainFile)}).  Export is performed without instantiation of a
	 * {@link DomainObject}.
	 * 
	 * @param file        the output file to write the exported info
	 * @param domainFile  the domain file to be exported (e.g., packed DB file)
	 * @param monitor     the task monitor
	 * @return true if the file was successfully exported; otherwise, false.  If the file
	 *   was not successfully exported, the message log should be checked to find the source of
	 *   the error.
	 *   
	 * @throws ExporterException if export error occurs
	 * @throws IOException if an IO error occurs
	 */
	public boolean export(File file, DomainFile domainFile, TaskMonitor monitor)
			throws ExporterException, IOException {
		throw new UnsupportedOperationException("DomainFile export not supported");
	}

	@Override
	final public String toString() {
		return getName();
	}
}
