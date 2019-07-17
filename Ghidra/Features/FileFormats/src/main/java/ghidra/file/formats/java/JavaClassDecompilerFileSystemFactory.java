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
package ghidra.file.formats.java;

import java.io.File;
import java.io.IOException;

import org.apache.commons.io.FilenameUtils;

import ghidra.file.jad.JadProcessWrapper;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryWithFile;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeBytesOnly;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import utilities.util.ArrayUtilities;

/**
 * Creates instances of {@link JavaClassDecompilerFileSystem}.
 */
public class JavaClassDecompilerFileSystemFactory implements
		GFileSystemFactoryWithFile<JavaClassDecompilerFileSystem>, GFileSystemProbeBytesOnly {

	@Override
	public int getBytesRequired() {
		return JavaClassConstants.MAGIC_BYTES.length;
	}

	@Override
	public boolean probeStartBytes(FSRL containerFSRL, byte[] startBytes) {
		return JadProcessWrapper.isJadPresent() &&
			ArrayUtilities.arrayRangesEquals(startBytes, 0, JavaClassConstants.MAGIC_BYTES, 0,
				JavaClassConstants.MAGIC_BYTES.length) &&
			"class".equalsIgnoreCase(FilenameUtils.getExtension(containerFSRL.getName()));
	}

	@Override
	public JavaClassDecompilerFileSystem create(FSRL containerFSRL, FSRLRoot targetFSRL,
			File containerFile, FileSystemService fsService, TaskMonitor monitor)
			throws IOException, CancelledException {

		JavaClassDecompilerFileSystem fs =
			new JavaClassDecompilerFileSystem(targetFSRL, fsService, monitor);
		return fs;
	}

}
