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
package ghidra.file.formats.android.oat;

import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.StructConverterUtil;
import ghidra.app.util.importer.MessageLog;
import ghidra.file.formats.android.dex.format.DexHeader;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public abstract class OatDexFile implements StructConverter {

	public static final String PREFIX = StructConverterUtil.parseName(OatDexFile.class);

	/**
	 * Returns the path string (not null terminated).
	 * @return the path string (not null terminated)
	 */
	abstract public String getDexFileLocation();

	/**
	 * Returns the checksum of the embedded dex files.
	 * @return the checksum of the embedded dex files
	 */
	abstract public int getDexFileChecksum();

	/**
	 * Returns the offset to the dex files, relative to the OATDATA symbol.
	 * @return the offset to the dex files
	 */
	abstract public int getDexFileOffset();

	/**
	 * Returns the embedded DEX header.
	 * @return the embedded DEX header
	 */
	abstract public DexHeader getDexHeader();

	/**
	 * Annotates the listing with data structures related to this object.
	 * @param oatHeader the OAT header to markup
	 * @param program the program to create markup
	 * @param monitor the task monitor
	 * @param log the message log
	 * @throws Exception if any error occur during markup
	 */
	abstract public void markup(OatHeader oatHeader, Program program, TaskMonitor monitor,
			MessageLog log) throws Exception;

	/**
	 * Is the DEX header stored in an external file (e.g. VDEX files).
	 * @return true if the DEX header is stored externally
	 */
	abstract public boolean isDexHeaderExternal();

}
