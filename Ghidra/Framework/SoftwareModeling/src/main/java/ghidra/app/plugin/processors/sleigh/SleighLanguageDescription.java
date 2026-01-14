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
package ghidra.app.plugin.processors.sleigh;

import java.util.*;

import generic.jar.ResourceFile;
import ghidra.program.model.lang.*;

/**
 * Class for holding Language identifiers
 */
public class SleighLanguageDescription extends BasicLanguageDescription {

	private ResourceFile defsFile; // defs file
	private ResourceFile specFile; // pspec specification file
	private ResourceFile manualIndexFile; // the manual index file
	private SleighLanguageFile languageFile; // sla, slaspec file

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
		this.truncatedSpaceMap = spaceTruncations;
	}

	/**
	 * @return set of address space names which have been identified for truncation
	 */
	public Set<String> getTruncatedSpaceNames() {
		if (truncatedSpaceMap == null) {
			return Set.of();
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
	 *            the specFile (.pspec) to associate with this description.
	 */
	public void setSpecFile(ResourceFile specFile) {
		this.specFile = specFile;
	}

	/**
	 * Get the specification (.pspec) file (if it exists)
	 * 
	 * @return specification file (.pspec)
	 */
	public ResourceFile getSpecFile() {
		return specFile;
	}

	/**
	 * Sets the {@link SleighLanguageFile} which represents the .sla and .slaspec files.
	 * 
	 * @param langFile {@link SleighLanguageFile} which represents the .sla and .slaspec files
	 */
	void setLanguageFile(SleighLanguageFile langFile) {
		this.languageFile = langFile;
	}

	/**
	 * Returns the {@link SleighLanguageFile} which represents the .sla and .slaspec files.
	 * 
	 * @return {@link SleighLanguageFile} which represents the .sla and .slaspec files
	 */
	public SleighLanguageFile getLanguageFile() {
		return languageFile;
	}

	public ResourceFile getManualIndexFile() {
		return manualIndexFile;
	}

	public void setManualIndexFile(ResourceFile manualIndexFile) {
		this.manualIndexFile = manualIndexFile;
	}

	/**
	 * Tests if two Sleigh languages are based on the same .sla file.
	 * 
	 * @param other {@link SleighLanguageDescription}
	 * @return true if the other {@link SleighLanguageDescription} uses the same .sla file
	 */
	public boolean isSameSleighLanguageFile(SleighLanguageDescription other) {
		return other != null &&
			languageFile.getSlaFile().equals(other.getLanguageFile().getSlaFile());
	}

}
