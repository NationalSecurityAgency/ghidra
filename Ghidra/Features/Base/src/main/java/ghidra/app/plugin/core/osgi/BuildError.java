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
package ghidra.app.plugin.core.osgi;

import generic.jar.ResourceFile;

/**
 * An error produced during {@link GhidraBundle#build()} with a time stamp
 */
public class BuildError {
	// the lastModified time of the source causing this error
	private final long lastModified;

	private final StringBuilder message = new StringBuilder();

	/**
	 * Construct an object to record error message produced for {@code sourceFile}
	 * @param sourceFile the file causing this error 
	 */
	public BuildError(ResourceFile sourceFile) {
		lastModified = sourceFile.lastModified();
	}

	/**
	 * Append {@code str} to the current error message
	 * 
	 * @param str the string to append 
	 */
	public void append(String str) {
		message.append(str);
	}

	/**
	 * @return the error message
	 */
	String getMessage() {
		return message.toString();
	}

	/**
	 * @return the last modified time of the source for this build error
	 */
	public long getLastModified() {
		return lastModified;
	}

}
