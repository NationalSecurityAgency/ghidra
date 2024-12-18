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

import java.io.*;
import java.util.*;

import org.apache.commons.io.FilenameUtils;

import ghidra.formats.gfilesystem.FSRL;
import ghidra.util.task.TaskMonitor;
import pdb.symbolserver.SymbolServer.StatusRequiresContext;

/**
 * A Pdb symbol server / symbol store, similar to the {@link LocalSymbolStore}, 
 * but limited to searching just the single directory that the original executable is located in.
 * <p>
 * 
 */
public class SameDirSymbolStore implements SymbolStore, StatusRequiresContext {

	/**
	 * Descriptive string
	 */
	public static String PROGRAMS_IMPORT_LOCATION_DESCRIPTION_STR = "Program's Import Location";

	/**
	 * Factory helper, indicates if the specified location is the special
	 * magic string that indicates the location is the "same dir" symbol store.
	 *  
	 * @param locationString Symbol server location string
	 * @return boolean true if the location string is the special magic "same dir" string (".")
	 */
	public static boolean isSameDirLocation(String locationString) {
		return ".".equals(locationString);
	}

	/**
	 * Reuse / abuse the {@link SameDirSymbolStore} to be the container/wrapper for an already known
	 * symbol file.  Useful to wrap a file that was picked by the user in an
	 * {@link SymbolFileLocation}.
	 * 
	 * @param symbolFile symbol file
	 * @param symbolFileInfo symbol file information
	 * @return a new {@link SymbolFileLocation} with a {@link SameDirSymbolStore} parent
	 */
	public static SymbolFileLocation createManuallySelectedSymbolFileLocation(File symbolFile,
			SymbolFileInfo symbolFileInfo) {
		SameDirSymbolStore samedirSymbolStore = new SameDirSymbolStore(symbolFile.getParentFile());
		SymbolFileLocation symbolFileLocation =
			new SymbolFileLocation(symbolFile.getName(), samedirSymbolStore, symbolFileInfo);
		return symbolFileLocation;
	}

	/**
	 * Creates a {@link SymbolServer} for the "Program's Import Location" item.  May return either
	 * a {@link SameDirSymbolStore} instance, or a {@link ContainerFileSymbolServer}.
	 *  
	 * @param locationString will be "."
	 * @param context {@link SymbolServerInstanceCreatorContext}
	 * @return new {@link SymbolServer}
	 */
	public static SymbolServer createInstance(String locationString,
			SymbolServerInstanceCreatorContext context) {
		FSRL programFSRL = context.getProgramFSRL();
		if (programFSRL != null && programFSRL.getNestingDepth() != 1) {
			return new ContainerFileSymbolServer(programFSRL);
		}
		String programFilename = programFSRL != null ? programFSRL.getName() : null;
		return new SameDirSymbolStore(context.getRootDir(), programFilename);
	}

	private final File rootDir;
	private final String programFilename;

	/**
	 * Create a new instance, based on the directory where the program was originally imported from.
	 * 
	 * @param rootDir directory path where the program was originally imported from, or null if not
	 * bound to an actual Program
	 */
	public SameDirSymbolStore(File rootDir) {
		this.rootDir = rootDir;
		this.programFilename = null;
	}

	public SameDirSymbolStore(File rootDir, String programFilename) {
		this.rootDir = rootDir;
		this.programFilename = programFilename;
	}

	@Override
	public File getAdminDir() {
		return rootDir;
	}

	@Override
	public File getFile(String path) {
		return new File(rootDir, path);
	}

	@Override
	public String giveFile(SymbolFileInfo symbolFileInfo, File f, String filename,
			TaskMonitor monitor) throws IOException {
		throw new IOException("Unsupported");
	}

	@Override
	public String putStream(SymbolFileInfo symbolFileInfo, SymbolServerInputStream streamInfo,
			String filename, TaskMonitor monitor) throws IOException {
		throw new IOException("Unsupported");
	}

	@Override
	public String getName() {
		return ".";
	}

	@Override
	public String getDescriptiveName() {
		return PROGRAMS_IMPORT_LOCATION_DESCRIPTION_STR +
			(isValid() ? " - " + rootDir.getPath() : "");
	}

	@Override
	public boolean isValid(TaskMonitor monitor) {
		return isValid();
	}

	private boolean isValid() {
		return rootDir != null && rootDir.isDirectory();
	}

	@Override
	public boolean exists(String filename, TaskMonitor monitor) {
		return isValid() && getFile(filename).isFile();
	}

	@Override
	public List<SymbolFileLocation> find(SymbolFileInfo fileInfo, Set<FindOption> findOptions,
			TaskMonitor monitor) {

		List<SymbolFileLocation> results = new ArrayList<>();

		if (isValid()) {
			LocalSymbolStore.searchLevel0(rootDir, this, fileInfo, findOptions, results, monitor);
			if (results.isEmpty() && programFilename != null) {
				// Search for renamed versions of the pdb file, using the current program's
				// name.  Note: if this shouldn't be automatic, add FindOption enum to control this
				List<String> altPdbfilenames = List.of(programFilename + ".pdb",
					FilenameUtils.getBaseName(programFilename) + ".pdb");
				for (String altPdbfilename : altPdbfilenames) {
					SymbolFileInfo altFileInfo = SymbolFileInfo.fromPdbIdentifiers(altPdbfilename,
						fileInfo.getIdentifiers());
					LocalSymbolStore.searchLevel0(rootDir, this, altFileInfo, findOptions, results,
						monitor);
					if (!results.isEmpty()) {
						break;
					}
				}
			}
		}

		return results;
	}

	@Override
	public SymbolServerInputStream getFileStream(String filename, TaskMonitor monitor)
			throws IOException {
		if (!isValid(monitor)) {
			throw new IOException("Unknown rootdir");
		}
		File file = getFile(filename);
		return new SymbolServerInputStream(new FileInputStream(file), file.length());
	}

	@Override
	public String getFileLocation(String filename) {
		return getFile(filename).getPath();
	}

	@Override
	public String toString() {
		return String.format("SameDirSymbolStore: [ dir: %s ]", rootDir);
	}

}
