/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.framework.options;

import java.io.File;

public class WrappedFile implements WrappedOption {
	private static final String FILE = "file";
	private File file;

	@Override
	public String toString() {
		return "WrappedFile: " + file.getAbsolutePath();
	}

	public WrappedFile(File file) {
		this.file = file;
	}

	public WrappedFile() {
		// need default constructor for reflection
	}

	@Override
	public void readState(SaveState saveState) {
		String filePath = saveState.getString(FILE, ".");
		file = new File(filePath);
	}

	@Override
	public void writeState(SaveState saveState) {
		saveState.putString(FILE, file.getAbsolutePath());
	}

	@Override
	public Object getObject() {
		return file;
	}

	@Override
	public OptionType getOptionType() {
		return OptionType.FILE_TYPE;
	}
}
