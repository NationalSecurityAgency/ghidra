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
package ghidra.app.plugin.core.analysis.rust.demangler;

/**
 * Enum representation of the available Rust demangler formats
 */
public enum RustDemanglerFormat {
	/** Automatic mangling format detection */
	AUTO("", Version.ALL),
	/** legacy mangling format */
	LEGACY("legacy", Version.ALL),
	/** v0 mangling format */
	V0("v0", Version.MODERN);

	/** the format option string used by the native demangler */
	private final String format;
	private final Version version;

	private RustDemanglerFormat(String format, Version version) {
		this.format = format;
		this.version = version;
	}

	/**
	 * Checks if this format is available in the deprecated rust demangler
	 * @return true if this format is available in the deprecated rust demangler
	 */
	public boolean isDeprecatedFormat() {
		return version == Version.DEPRECATED || version == Version.ALL;
	}

	/**
	 * Checks if this format is available in a modern version of the rust demangler
	 * @return true if this format is available in a modern version of the rust demangler
	 */
	public boolean isModernFormat() {
		return version == Version.MODERN || version == Version.ALL;
	}

	/**
	 * Checks if this format is available for the specified demangler
	 * @param isDeprecated true for the deprecated demangler, false for the modern demangler
	 * @return true if the format is available
	 */
	public boolean isAvailable(boolean isDeprecated) {
		return isDeprecated ? isDeprecatedFormat() : isModernFormat();
	}

	/**
	 * Gets the format option to be passed to the demangler via the <code>-s</code> option
	 * @return the format option to be passed to the demangler
	 */
	public String getFormat() {
		return format;
	}

	private enum Version {
		DEPRECATED, MODERN, ALL
	}
}
