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
package utilities.util;

import generic.jar.ResourceFile;

/**
 * A simple class that holds info relating to the result of verifying a file's existence and
 * proper usage of case.
 */
public class FileResolutionResult {

	public static enum FileResolutionStatus {
		OK, FileDoesNotExist, NotProperlyCaseDependent;
	}

	private static FileResolutionResult OK_RESULT =
		new FileResolutionResult(FileResolutionStatus.OK, "");

	public static FileResolutionResult doesNotExist(ResourceFile file) {
		String message = "File does not exist: " + file;
		return new FileResolutionResult(FileResolutionStatus.FileDoesNotExist, message);
	}

	public static FileResolutionResult notCaseDependent(String canonicalPath, String userPath) {
		String message = "Case difference found:\n\tCanonical path: " + canonicalPath +
			"\n\tUser path: " + userPath;
		return new FileResolutionResult(FileResolutionStatus.NotProperlyCaseDependent, message);
	}

	public static FileResolutionResult ok() {
		return OK_RESULT;
	}

	public static FileResolutionResult createDoesNotExistResult() {
		return null;
	}

	private final FileResolutionStatus status;
	private final String message;

	private FileResolutionResult(FileResolutionStatus status, String message) {
		this.status = status;
		this.message = message;
	}

	public FileResolutionStatus getStatus() {
		return status;
	}

	public String getMessage() {
		return message;
	}

	public boolean isOk() {
		return status == FileResolutionStatus.OK;
	}
}
