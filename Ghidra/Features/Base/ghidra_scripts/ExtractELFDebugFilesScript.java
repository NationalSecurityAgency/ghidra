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
// Bulk extracts ELF external debug files from distro container files (rpm, ddeb, etc) so that
// the DWARF analyzer can find them using the "Edit | DWARF External Debug Config" location.
// 
// When using this script, do not co-mingle different architectures or versions of debug files in
// the same directory as debug file names may conflict.
//
// Known issues: symlinks between different locations inside the debug package are not extracted,
// so some layout schemes where a single debug binary file is present in both the .build-id directory
// and the /usr/lib/, /usr/bin/, etc directory will not fully work.
//
// @category DWARF
import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Set;

import org.apache.commons.io.FilenameUtils;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.util.exception.CancelledException;
import utilities.util.FileUtilities;

public class ExtractELFDebugFilesScript extends GhidraScript {
	private static final Set<String> containerExts =
		Set.of("ddeb", "tar", "xz", "rpm", "tgz", "deb", "srpm", "cpio");

	private FileSystemService fsService;
	private int fileCount;

	@Override
	protected void run() throws Exception {
		fsService = FileSystemService.getInstance();

		File baseDir = askDirectory("Debug Packages Directory", "Select");
		if (baseDir == null) {
			return;
		}
		File destDir = askDirectory("Extract Destination Directory", "Select");
		if (destDir == null) {
			return;
		}

		println("Source directory: " + baseDir);
		println("Destination directory: " + destDir);
		try (FileSystemRef fsRef =
			fsService.probeFileForFilesystem(fsService.getLocalFSRL(baseDir), monitor, null)) {
			processDir(fsRef.getFilesystem().lookup(null), destDir);
		}
		println("Extracted: " + fileCount);
	}

	void processDir(GFile dir, File destDir) throws IOException, CancelledException {
		List<GFile> listing = dir.getListing();
		for (GFile file : listing) {
			monitor.checkCancelled();
			if (file.isDirectory()) {
				continue;
			}
			String extension = FilenameUtils.getExtension(file.getName()).toLowerCase();
			if (containerExts.contains(extension)) {
				try (FileSystemRef fsRef =
					fsService.probeFileForFilesystem(file.getFSRL(), monitor, null)) {
					if (fsRef == null) {
						continue;
					}

					processDir(fsRef.getFilesystem().lookup(null), destDir);
				}
			}
			else if ("debug".equalsIgnoreCase(extension)) {
				extractDebugFileToDestDir(file, destDir);
			}
		}
		for (GFile file : listing) {
			monitor.checkCancelled();
			if (file.isDirectory()) {
				processDir(file, destDir);
			}
		}
	}

	private void extractDebugFileToDestDir(GFile file, File destDir)
			throws CancelledException, IOException {
		File destFile = new File(destDir, file.getPath()).getCanonicalFile();
		if (!FileUtilities.isPathContainedWithin(destDir, destFile)) {
			throw new IOException("Bad path / filename: " + file);
		}
		if (destFile.exists()) {
			printerr("Duplicate debug file: " + file.getFSRL() + ", " + destFile);
			return;
		}

		try (ByteProvider bp = file.getFilesystem().getByteProvider(file, monitor)) {
			FileUtilities.checkedMkdirs(destFile.getParentFile());
			FSUtilities.copyByteProviderToFile(bp, destFile, monitor);
			fileCount++;
		}
		catch (IOException e) {
			printerr("Error extracting file: " + file + ", " + e.getMessage());
		}
	}
}
