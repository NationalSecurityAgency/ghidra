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
package ghidra.app.plugin.core.sourcefilestable;

import ghidra.program.database.sourcemap.SourceFile;
import ghidra.program.database.sourcemap.SourceFileIdType;
import ghidra.program.model.sourcemap.SourceFileManager;

/**
 * The row object used by {@link SourceFilesTableModel}.
 */
public class SourceFileRowObject {

	private SourceFile sourceFile;
	private int numEntries; // cache this since it's expensive to compute

	/**
	 * Constructor
	 * @param sourceFile source file
	 * @param sourceManager source file manager
	 */
	public SourceFileRowObject(SourceFile sourceFile, SourceFileManager sourceManager) {
		this.sourceFile = sourceFile;
		numEntries = sourceManager.getSourceMapEntries(sourceFile).size();
	}

	public String getFileName() {
		return sourceFile.getFilename();
	}

	public String getPath() {
		return sourceFile.getPath();
	}

	public int getNumSourceMapEntries() {
		return numEntries;
	}

	public SourceFile getSourceFile() {
		return sourceFile;
	}

	public SourceFileIdType getSourceFileIdType() {
		return sourceFile.getIdType();
	}

}
