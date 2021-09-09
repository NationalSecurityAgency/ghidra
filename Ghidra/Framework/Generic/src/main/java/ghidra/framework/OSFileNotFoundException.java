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
package ghidra.framework;

import java.io.FileNotFoundException;

/**
 * Signals that an attempt to find a Ghidra "OS-file" (native binary) has failed.
 * <p>
 * This exception provides a consistent way to display information about the missing OS-file that 
 * will aid in error reporting and debugging.
 */
public class OSFileNotFoundException extends FileNotFoundException {

	private Platform platform;
	/**
	 * Creates a new {@link OSFileNotFoundException}
	 * 
	 * @param platform The {@link Platform} associated with this exception
	 * @param moduleName The module name associated with this exception
	 * @param fileName The file name associated with this exception, from the given module
	 */
	public OSFileNotFoundException(Platform platform, String moduleName, String fileName) {
		super(String.format("%sos/%s/%s does not exist", moduleName != null ? moduleName + "/" : "",
			platform.getDirectoryName(), fileName));
		this.platform = platform;
	}

	/**
	 * Creates a new {@link OSFileNotFoundException} with an unknown module
	 * 
	 * @param platform The {@link Platform} associated with this exception
	 * @param fileName The file name associated with this exception, from an unknown module
	 */
	public OSFileNotFoundException(Platform platform, String fileName) {
		this(platform, null, fileName);
	}

	/**
	 * Creates a new {@link OSFileNotFoundException} for the current {@link Platform}
	 * 
	 * @param moduleName The module name associated with this exception
	 * @param fileName The file name associated with this exception, from the given module
	 */
	public OSFileNotFoundException(String moduleName, String fileName) {
		this(Platform.CURRENT_PLATFORM, moduleName, fileName);
	}

	/**
	 * Creates a new {@link OSFileNotFoundException} for the current {@link Platform} with an
	 * unknown module
	 * 
	 * @param fileName The file name associated with this exception, from an unknown module
	 */
	public OSFileNotFoundException(String fileName) {
		this(Platform.CURRENT_PLATFORM, null, fileName);
	}

	/** Gets the {@link Platform} associated with this exception
	 * 
	 * @return The {@link Platform} associated with this exception
	 */
	public Platform getPlatform() {
		return platform;
	}
}
