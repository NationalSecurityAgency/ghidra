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
package ghidra.program.model.lang;

import generic.jar.ResourceFile;

import java.util.*;

/**
 * Class for holding Language identifiers
 */
public class SleighLanguageDescription extends BasicLanguageDescription {

	private ResourceFile defsFile; // defs file
	private ResourceFile specFile; // specification file
	private ResourceFile slaFile; // just cramming this in here until major cleanup
	private ResourceFile manualIndexFile; // the manual index file

	private Map<String, Integer> truncatedSpaceMap;

	/**
	 * Construct a new language description
	 * @param id the name of the language
	 * @param description language description text
	 * @param processor processor name/family
	 * @param endian data endianess
	 * @param instructionEndian instruction endianess
	 * @param size processor size 
	 * @param variant processor variant name
	 * @param version the major version of the language.
	 * @param minorVersion minor version of language
	 * @param deprecated true if this language should only be used for existing programs.
	 * @param spaceTruncations address space truncations (or null)
	 * @param compilerSpecDescriptions one or more compiler spec descriptions
	 * @param externalNames collection of external tools' names for the language
	 */
	public SleighLanguageDescription(LanguageID id, String description, Processor processor,
			Endian endian, Endian instructionEndian, int size, String variant, int version,
			int minorVersion, boolean deprecated, Map<String, Integer> spaceTruncations,
			List<CompilerSpecDescription> compilerSpecDescriptions,
			Map<String, List<String>> externalNames) {
		super(id, processor, endian, instructionEndian, size, variant, description, version,
			minorVersion, deprecated, compilerSpecDescriptions, externalNames);
		this.specFile = null;
		this.slaFile = null;
		this.manualIndexFile = null;
		this.truncatedSpaceMap = spaceTruncations;
	}

	/**
	 * @return set of address space names which have been identified for truncation
	 */
	@SuppressWarnings("unchecked")
	public Set<String> getTruncatedSpaceNames() {
		if (truncatedSpaceMap == null) {
			return Collections.EMPTY_SET;
		}
		return truncatedSpaceMap.keySet();
	}

	/**
	 * Get the truncated space size for the specified address space
	 * @param spaceName address space name
	 * @return truncated space size in bytes
	 * @throws NoSuchElementException
	 */
	public int getTruncatedSpaceSize(String spaceName) throws NoSuchElementException {
		if (truncatedSpaceMap == null) {
			throw new NoSuchElementException();
		}
		return truncatedSpaceMap.get(spaceName);
	}

	/**
	 * Set the (optional) specification file associated with this language
	 * 
	 * @param defsFile
	 *            the specFile to associate with this description.
	 */
	public void setDefsFile(ResourceFile defsFile) {
		this.defsFile = defsFile;
	}

	/**
	 * Get the specification file (if it exists)
	 * 
	 * @return specification file
	 */
	public ResourceFile getDefsFile() {
		return defsFile;
	}

	/**
	 * Set the (optional) specification file associated with this language
	 * 
	 * @param specFile
	 *            the specFile to associate with this description.
	 */
	public void setSpecFile(ResourceFile specFile) {
		this.specFile = specFile;
	}

	/**
	 * Get the specification file (if it exists)
	 * 
	 * @return specification file
	 */
	public ResourceFile getSpecFile() {
		return specFile;
	}

	/**
	 * @param slaFile
	 */
	public void setSlaFile(ResourceFile slaFile) {
		this.slaFile = slaFile;
	}

	/**
	 * @return
	 */
	public ResourceFile getSlaFile() {
		return slaFile;
	}

	public ResourceFile getManualIndexFile() {
		return manualIndexFile;
	}

	public void setManualIndexFile(ResourceFile manualIndexFile) {
		this.manualIndexFile = manualIndexFile;
	}
}
