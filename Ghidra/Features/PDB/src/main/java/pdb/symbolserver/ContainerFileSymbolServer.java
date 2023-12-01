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

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Set;

import org.apache.commons.io.FilenameUtils;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.formats.gfilesystem.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Companion to the {@link SameDirSymbolStore}, handles the case where the imported binary
 * was located in a container file (eg. zip file).
 * <p>
 * Instances of this class are conditionally created by the 
 * {@link SameDirSymbolStore#createInstance(String, SymbolServerInstanceCreatorContext) registry factory method}
 * when it detects that the imported binary's {@link FSRL} isn't a simple local file.
 */
public class ContainerFileSymbolServer implements SymbolServer {

	private final FileSystemService fsService;
	private final FSRLRoot fsFSRL;
	private final String subdir;

	public ContainerFileSymbolServer(FSRL programFSRL) {
		this.fsFSRL = programFSRL.getFS();
		this.subdir = FilenameUtils.getFullPath(programFSRL.getPath());
		this.fsService = FileSystemService.getInstance();
	}

	@Override
	public String getName() {
		return ".";
	}

	@Override
	public String getDescriptiveName() {
		return SameDirSymbolStore.PROGRAMS_IMPORT_LOCATION_DESCRIPTION_STR + " - " +
			fsFSRL.toPrettyFullpathString();
	}

	@Override
	public boolean isValid(TaskMonitor monitor) {
		return true;
	}

	@Override
	public boolean exists(String filename, TaskMonitor monitor) {
		try (RefdFile file = getFile(filename, monitor)) {
			return file != null;
		}
		catch (IOException e1) {
			// fall thru
		}
		return false;
	}

	private RefdFile getFile(String filename, TaskMonitor monitor) {
		try (FileSystemRef fsRef = fsService.getFilesystem(fsFSRL, monitor)) {
			if (fsRef != null) {
				GFileSystem fs = fsRef.getFilesystem();
				String path = FSUtilities.appendPath(subdir, filename);
				GFile file = fs.lookup(path);
				if (file != null && !file.isDirectory()) {
					return new RefdFile(fsRef.dup(), file);
				}
			}
		}
		catch (IOException | CancelledException e) {
			// fall thru
		}
		return null;
	}

	@Override
	public List<SymbolFileLocation> find(SymbolFileInfo fileInfo, Set<FindOption> findOptions,
			TaskMonitor monitor) {

		try (RefdFile fref = getFile(fileInfo.getName(), monitor)) {
			if (fref != null) {
				GFile file = fref.file;
				GFileSystem fs = file.getFilesystem();
				try (AbstractPdb pdb = PdbParser.parse(fs.getByteProvider(file, monitor),
					new PdbReaderOptions(), monitor)) {
					PdbIdentifiers pdbIdent = pdb.getIdentifiers();
					SymbolFileInfo foundInfo =
						SymbolFileInfo.fromPdbIdentifiers(file.getName(), pdbIdent);
					return List.of(new SymbolFileLocation(fileInfo.getName(), this, foundInfo));
				}
			}
		}
		catch (Exception e) {
			// fall thru
		}
		return List.of();
	}

	@Override
	public SymbolServerInputStream getFileStream(String filename, TaskMonitor monitor)
			throws IOException {
		try (RefdFile fref = getFile(filename, monitor)) {
			if (fref != null) {
				GFile file = fref.file;
				InputStream is = file.getFilesystem().getInputStream(file, monitor);
				is = new RefdInputStream(fref.fsRef.dup(), is);
				return new SymbolServerInputStream(is, file.getLength());
			}
		}
		catch (CancelledException e) {
			// fall thru
		}
		throw new IOException();
	}

	@Override
	public String getFileLocation(String filename) {
		return fsFSRL.withPath(filename).toPrettyFullpathString();
	}

	@Override
	public boolean isLocal() {
		return true;
	}

	@Override
	public String toString() {
		return "ContainerFileSymbolServer: [ fsrl: %s ]".formatted(fsFSRL);
	}

}
