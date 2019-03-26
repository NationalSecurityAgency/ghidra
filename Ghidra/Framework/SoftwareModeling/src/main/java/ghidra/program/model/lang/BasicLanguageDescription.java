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

import java.util.*;

public class BasicLanguageDescription implements LanguageDescription {
	private final LanguageID languageId;
	private final Processor processor;
	private final Endian endian;
	private final Endian instructionEndian;
	private final int size;
	private final String variant;
	private final String description;
	private final int version;
	private final int minorVersion;
	private final boolean deprecated;
	private final LinkedHashMap<CompilerSpecID, CompilerSpecDescription> compatibleCompilerSpecs;
	private final Map<String, List<String>> externalNames;

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((languageId == null) ? 0 : languageId.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (!(obj instanceof LanguageDescription))
			return false;
		final LanguageDescription other = (LanguageDescription) obj;
		if (languageId == null) {
			return other.getLanguageID() == null;
		}
		return languageId.equals(other.getLanguageID());
	}

	public BasicLanguageDescription(LanguageID id, Processor processor, Endian endian,
			Endian instructionEndian, int size, String variant, String description, int version,
			int minorVersion, boolean deprecated, CompilerSpecDescription compilerSpec,
			Map<String, List<String>> externalNames) {
		this(id, processor, endian, instructionEndian, size, variant, description, version,
			minorVersion, deprecated, Collections.singletonList(compilerSpec), externalNames);
	}

	public BasicLanguageDescription(LanguageID id, Processor processor, Endian endian,
			Endian instructionEndian, int size, String variant, String description, int version,
			int minorVersion, boolean deprecated, List<CompilerSpecDescription> compilerSpecs,
			Map<String, List<String>> externalNames) {

		this.description = description;
		this.endian = endian;
		this.minorVersion = minorVersion;
		this.version = version;
		this.processor = processor;
		this.size = size;
		this.variant = variant;
		this.deprecated = deprecated;
		this.languageId = id;
		this.instructionEndian = instructionEndian;

		compatibleCompilerSpecs = new LinkedHashMap<CompilerSpecID, CompilerSpecDescription>();
		for (CompilerSpecDescription compilerSpecDescription : compilerSpecs) {
			compatibleCompilerSpecs.put(compilerSpecDescription.getCompilerSpecID(),
				compilerSpecDescription);
		}
		this.externalNames = externalNames;
	}

	public String getDescription() {
		return description;
	}

	public Endian getEndian() {
		return endian;
	}

	@Override
	public Endian getInstructionEndian() {
		return instructionEndian;
	}

	@Override
	public LanguageID getLanguageID() {
		return languageId;
	}

	public int getMinorVersion() {
		return minorVersion;
	}

	public int getVersion() {
		return version;
	}

	public Processor getProcessor() {
		return processor;
	}

	public int getSize() {
		return size;
	}

	public String getVariant() {
		return variant;
	}

	public boolean isDeprecated() {
		return deprecated;
	}

	public List<CompilerSpecDescription> getCompatibleCompilerSpecDescriptions() {
		return new ArrayList<CompilerSpecDescription>(compatibleCompilerSpecs.values());
	}

	public CompilerSpecDescription getCompilerSpecDescriptionByID(CompilerSpecID compilerSpecID)
			throws CompilerSpecNotFoundException {
		CompilerSpecDescription compilerSpecDescription =
			compatibleCompilerSpecs.get(compilerSpecID);
		if (compilerSpecDescription == null) {
			throw new CompilerSpecNotFoundException(getLanguageID(), compilerSpecID);
		}
		return compilerSpecDescription;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(processor);
		sb.append("/");
		sb.append(endian);
		sb.append("/");
		sb.append(size);
		sb.append("/");
		sb.append(variant);
		return sb.toString();
	}

	@Override
	public List<String> getExternalNames(String key) {
		List<String> result = null;
		if (key != null && this.externalNames != null) {
			List<String> localResults = externalNames.get(key);
			if (localResults != null) {
				result = new ArrayList<String>(localResults);
			}
		}
		return result;
	}
}
