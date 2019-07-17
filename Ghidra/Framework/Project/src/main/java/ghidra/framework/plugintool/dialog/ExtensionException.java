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
package ghidra.framework.plugintool.dialog;

import java.io.File;

import ghidra.util.exception.UsrException;

/**
 * Defines an exception that can be thrown by {@link ExtensionUtils}. This is intended to provide
 * detailed information about issues that arise during installation (or removal) of 
 * Extensions. 
 * 
 */
public class ExtensionException extends UsrException {

	/** Provides more detail as to the specific source of the exception. */
	public enum ExtensionExceptionType {

		/** Thrown if the required installation location does not exist */
		INVALID_INSTALL_LOCATION,

		/** Thrown when installing an extension to an existing location */
		DUPLICATE_FILE_ERROR,

		/** Thrown when there is a problem reading/extracting a zip file during installation */
		ZIP_ERROR,

		/** Thrown when there is a problem copying a folder during an installation */
		COPY_ERROR,

		/** Thrown when the user cancels the installation	 */
		INSTALL_CANCELLED
	}

	private ExtensionExceptionType exceptionType;
	private File errorFile = null;  // If there's a file relevant to the exception, populate this.

	public ExtensionException(String msg, ExtensionExceptionType exceptionType) {
		super(msg);
		this.exceptionType = exceptionType;
	}
	
	public ExtensionException(String msg, ExtensionExceptionType exceptionType, File errorFile) {
		super(msg);
		this.errorFile = errorFile;
		this.exceptionType = exceptionType;
	}

	public ExtensionExceptionType getExceptionType() {
		return exceptionType;
	}
	
	public File getErrorFile() {
		return errorFile;
	}
}
