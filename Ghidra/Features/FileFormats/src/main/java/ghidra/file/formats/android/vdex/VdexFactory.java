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
package ghidra.file.formats.android.vdex;

import java.io.File;
import java.io.IOException;

import org.apache.commons.io.FilenameUtils;

import ghidra.app.util.bin.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public final class VdexFactory {

	/**
	 * Returns an VDEX Header for the specified version.
	 * @param reader the binary reader
	 * @return the new VDEX header
	 * @throws IOException if an error occurs creating new VDEX header
	 * @throws UnsupportedVdexVersionException when the provided version is invalid or not yet implemented.
	 */
	public static VdexHeader getVdexHeader(BinaryReader reader)
			throws IOException, UnsupportedVdexVersionException {
		String magic = reader.readAsciiString(0, VdexConstants.MAGIC.length());
		String version = reader.readAsciiString(4, 4);
		if (magic.equals(VdexConstants.MAGIC)) {
			if (VdexConstants.isSupportedVersion(version)) {
				if (version.equals(VdexConstants.VERSION_OREO_RELEASE) ||
					version.equals(VdexConstants.VERSION_OREO_M2_RELEASE)) {
					return new VdexHeader_Oreo(reader);
				}
				if (version.equals(VdexConstants.VERSION_PIE_RELEASE)) {
					return new VdexHeader_Pie(reader);
				}
				if (version.equals(VdexConstants.VERSION_10_RELEASE)) {
					return new VdexHeader_10(reader);
				}
				if (version.equals(VdexConstants.VERSION_11_RELEASE)) {
					return new VdexHeader_11(reader);
				}
			}
		}
		throw new UnsupportedVdexVersionException(magic, version);
	}

	public static VdexHeader loadVdexHeader(Program program, TaskMonitor monitor, MessageLog log) {

		if (program == null) {
			return null;
		}

		String vdexProgramName = FilenameUtils.removeExtension(program.getName());

		//first, look in current project for VDEX file....

		DomainFile domainFile = program.getDomainFile();
		DomainFolder parentFolder = domainFile.getParent();
		VdexHeader vdexHeader =
			scanProjectFolder(parentFolder, vdexProgramName, program, monitor, log);
		if (vdexHeader == null) {
			vdexHeader =
				scanProjectFolder(parentFolder.getParent(), vdexProgramName, program, monitor, log);
		}
		if (vdexHeader != null) {
			return vdexHeader;
		}

		//then, try to locate the VDEX on disk, in same folder where binary was imported....

		String oatFilePath = program.getExecutablePath();

		if (oatFilePath.endsWith(".odex") || oatFilePath.endsWith(".oat")) {
			String vdexFilePath = FilenameUtils.removeExtension(oatFilePath);
			File vdexFile = new File(vdexFilePath);
			try (ByteProvider vdexProvider = new RandomAccessByteProvider(vdexFile)) {
				BinaryReader vdexReader =
					new BinaryReader(vdexProvider, !program.getLanguage().isBigEndian());
				vdexHeader = getVdexHeader(vdexReader);
				vdexHeader.parse(vdexReader, monitor);
				return vdexHeader;
			}
			catch (Exception e) {
				log.appendMsg("Unable to locate matching VDEX.");
			}
		}

		return null;
	}

	private static VdexHeader scanProjectFolder(DomainFolder parentFolder, String vdexProgramName,
			Program program, TaskMonitor monitor, MessageLog log) {

		DomainFile child = parentFolder.getFile(vdexProgramName);
		if (child != null) {
			try {
				Object consumer = new Object();
				Program vdexProgram =
					(Program) child.getDomainObject(consumer, true, true, monitor);
				try {
					ByteProvider vdexProvider = new MemoryByteProvider(vdexProgram.getMemory(),
						vdexProgram.getMinAddress());
					BinaryReader vdexReader =
						new BinaryReader(vdexProvider, !program.getLanguage().isBigEndian());
					VdexHeader vdexHeader = getVdexHeader(vdexReader);
					vdexHeader.parse(vdexReader, monitor);
					return vdexHeader;
				}
				finally {
					vdexProgram.release(consumer);
				}
			}
			catch (Exception e) {
				log.appendMsg("Unable to locate matching VDEX.");
			}
		}
		return null;
	}

}
