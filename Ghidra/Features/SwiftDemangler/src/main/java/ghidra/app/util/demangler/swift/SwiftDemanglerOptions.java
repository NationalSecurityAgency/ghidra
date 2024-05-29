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
package ghidra.app.util.demangler.swift;

import java.io.File;

import ghidra.app.util.demangler.DemanglerOptions;

/**
 * Swift demangler options
 */
public class SwiftDemanglerOptions extends DemanglerOptions {

	public static final String INCOMPLETE_PREFIX = "$";
	public static final String UNSUPPORTED_PREFIX = "$$";

	private File swiftDir;
	private boolean useIncompletePrefix;
	private boolean useUnsupportedPrefix;

	/**
	 * Gets the Swift directory
	 * <p>
	 * If the Swift directory is on the PATH environment variable, this may return null
	 * 
	 * @return The Swift directory
	 */
	public File getSwiftDir() {
		return swiftDir;
	}

	/**
	 * Sets the Swift directory
	 * <p>
	 * If the Swift directory is on the PATH environment variable, it is fine to set this to 
	 * null
	 * 
	 * @param swiftDir The Swift directory
	 */
	public void setSwiftDir(File swiftDir) {
		this.swiftDir = swiftDir;
	}

	/**
	 * {@return the "incomplete prefix" character to use in label names}
	 */
	public String getIncompletePrefix() {
		return useIncompletePrefix ? INCOMPLETE_PREFIX : "";
	}

	/**
	 * Sets whether or not to use an "incomplete prefix" character in label names
	 * 
	 * @param incompletePrefix True if labels should include an "incomplete prefix" character
	 *   in their name; otherwise, false
	 */
	public void setIncompletePrefix(boolean incompletePrefix) {
		this.useIncompletePrefix = incompletePrefix;
	}

	/**
	 * {@return the "unsupported prefix" character to use in label names}
	 */
	public String getUnsupportedPrefix() {
		return useUnsupportedPrefix ? UNSUPPORTED_PREFIX : "";
	}

	/**
	 * Sets whether or not to use an "unsupported prefix" character in label names
	 * 
	 * @param unsupportedPrefix True if labels should include an "unsupported prefix" character
	 *   in their name; otherwise, false
	 */
	public void setUnsupportedPrefix(boolean unsupportedPrefix) {
		this.useUnsupportedPrefix = unsupportedPrefix;
	}
}
