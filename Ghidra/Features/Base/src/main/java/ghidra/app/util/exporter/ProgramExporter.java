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

import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;

/**
 * {@link ProgramExporter} provides an abstract {@link Exporter} implementation for
 * {@link Program} objects.
 */
public abstract class ProgramExporter extends Exporter {

	/**
	 * Constructs a new {@link Program} exporter.
	 * @param name       the display name of this exporter
	 * @param extension  the default extension for this exporter
	 * @param help       the help location for this exporter
	 */
	protected ProgramExporter(String name, String extension, HelpLocation help) {
		super(name, extension, help);
	}

	/**
	 * Get an exportable Program instance from the specified DomainObject instance.
	 * The specified instance must satisfy {@link #canExportDomainObject(Class)}.
	 * @param domainObj domain object from which a Program may be derived.
	 * @return Program instance
	 * @throws ClassCastException if domain object class does not satisfy 
	 * {@link #canExportDomainObject(Class)}.
	 */
	protected Program getProgram(DomainObject domainObj) throws ClassCastException {
		return (Program) domainObj;
	}

	@Override
	public boolean canExportDomainObject(Class<? extends DomainObject> domainObjectClass) {
		return Program.class.isAssignableFrom(domainObjectClass);
	}

}
