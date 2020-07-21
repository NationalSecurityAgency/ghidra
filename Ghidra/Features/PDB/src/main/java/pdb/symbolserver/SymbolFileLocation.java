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
package pdb.symbolserver;

import java.util.Objects;

/**
 * Represents a symbol file on a {@link SymbolServer} or an associated file.
 */
public class SymbolFileLocation {
	private final SymbolFileInfo fileInfo;
	private final String path;
	private final SymbolServer symbolServer;

	/**
	 * Creates a new instance.
	 * 
	 * @param path raw path to file (relative to the {@link SymbolServer})
	 * @param symbolServer {@link SymbolServer} the file resides on
	 * @param fileInfo the {@link SymbolFileInfo pdb file} that this file is associated with
	 */
	public SymbolFileLocation(String path, SymbolServer symbolServer, SymbolFileInfo fileInfo) {
		this.path = path;
		this.symbolServer = symbolServer;
		this.fileInfo = fileInfo;
	}

	/**
	 * The raw path inside the SymbolServer to the file.
	 * 
	 * @return raw path inside the SymbolServer to the file
	 */
	public String getPath() {
		return path;
	}

	/**
	 * The {@link SymbolServer} that holds the file.
	 * 
	 * @return the {@link SymbolServer} that holds the file
	 */
	public SymbolServer getSymbolServer() {
		return symbolServer;
	}

	/**
	 * The {@link SymbolFileInfo pdb file} that this file is associated with.
	 *  
	 * @return the {@link SymbolFileInfo pdb file} that this file is associated with
	 */
	public SymbolFileInfo getFileInfo() {
		return fileInfo;
	}

	/**
	 * Returns true if this file is an 'exact match' for the
	 * specified {@link SymbolFileInfo other pdb file}.
	 * 
	 * @param otherSymbolFileInfo the other pdb file's info
	 * @return boolean true if exact match (GUID & age match), false if not an exact match
	 */
	public boolean isExactMatch(SymbolFileInfo otherSymbolFileInfo) {
		return fileInfo.isExactMatch(otherSymbolFileInfo);
	}

	/**
	 * The 'absolute' location of this file, including the symbol server's location.
	 * 
	 * @return a string representing the 'absolute' location of this file
	 */
	public String getLocationStr() {
		return symbolServer.getFileLocation(path);
	}

	@Override
	public String toString() {
		return path + " in " + symbolServer.getName() + " for " + fileInfo.getDescription();
	}

	@Override
	public int hashCode() {
		return Objects.hash(fileInfo, path, symbolServer);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		SymbolFileLocation other = (SymbolFileLocation) obj;
		return Objects.equals(fileInfo, other.fileInfo) && Objects.equals(path, other.path) &&
			symbolServer == other.symbolServer;
	}

}
