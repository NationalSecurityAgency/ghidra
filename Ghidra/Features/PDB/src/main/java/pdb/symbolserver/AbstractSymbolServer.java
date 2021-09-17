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
import java.util.List;
import java.util.Set;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.StringUtils;

import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * Common functionality of File and Http symbol servers.
 */
public abstract class AbstractSymbolServer implements SymbolServer {
	protected static final String INDEX_TWO_FILENAME = "index2.txt";
	protected static final String PINGME_FILENAME = "pingme.txt"; // per MS custom

	protected int storageLevel = -1;

	@Override
	public List<SymbolFileLocation> find(SymbolFileInfo symbolFileInfo, Set<FindOption> options,
			TaskMonitor monitor) {
		if (StringUtils.isBlank(symbolFileInfo.getName())) {
			Msg.warn(this, "Unable to search for empty filename: " + symbolFileInfo);
			return List.of();
		}

		initStorageLevelIfNeeded(monitor);

		try {
			// "ke/kernelstuff.pdb/12345ABCFF0/"
			String uniqueFileDir = getUniqueFileDir(symbolFileInfo);

			// "ke/kernelstuff.pdb/12345ABCFF0/kernelstuff.pdb" or
			// "ke/kernelstuff.pdb/12345ABCFF0/kernelstuff.pd_"
			String filePath = getFirstExists(uniqueFileDir, monitor, symbolFileInfo.getName(),
				getCompressedFilename(symbolFileInfo));

			return (filePath != null)
					? List.of(new SymbolFileLocation(filePath, this, symbolFileInfo))
					: List.of();
		}
		catch (IOException ioe) {
			Msg.warn(this, "Error searching for " + symbolFileInfo.getName(), ioe);
			return List.of();
		}
	}

	protected int detectStorageLevel(TaskMonitor monitor) {
		return exists(INDEX_TWO_FILENAME, monitor) ? 2 : 1;
	}

	protected void initStorageLevelIfNeeded(TaskMonitor monitor) {
		if (storageLevel < 0) {
			storageLevel = detectStorageLevel(monitor);
		}
	}

	protected String getFileDir(String filename) throws IOException {
		switch (storageLevel) {
			case 0:
				return "";
			case 1:
				return filename + "/";
			case 2:
				if (filename.length() <= 2) {
					throw new IOException(
						"Symbol filename too short to store in two-level index: " + filename);
				}
				return filename.substring(0, 2).toLowerCase() + "/" + filename + "/";
			default:
				throw new IllegalArgumentException(
					"Unsupported Symbol Server storage level: " + storageLevel);
		}
	}

	protected String getUniqueFileDir(SymbolFileInfo symbolFileInfo) throws IOException {
		switch (storageLevel) {
			case 0:
				return "";
			case 1:
			case 2:
				// "ke/kernelstuff.pdb/" or just "kernelstuff.pdb/"
				String fileRoot = getFileDir(symbolFileInfo.getName());

				// "ke/kernelstuff.pdb/12345ABCFF0/"
				String uniqueFileDir = fileRoot + symbolFileInfo.getUniqueDirName() + "/";

				return uniqueFileDir;
			default:
				throw new IllegalArgumentException(
					"Unsupported Symbol Server storage level: " + storageLevel);
		}
	}

	protected String getFirstExists(String subDir, TaskMonitor monitor, String... filenames) {
		for (String filename : filenames) {
			String pathname = subDir + filename;
			if (exists(pathname, monitor)) {
				return pathname;
			}
		}
		return null;
	}

	static String makeCompressedExtension(String fileTypeExtension) {
		return (!fileTypeExtension.isEmpty()
				? fileTypeExtension.substring(0, fileTypeExtension.length() - 1)
				: "") +
			"_";
	}

	static String getCompressedFilename(SymbolFileInfo symbolFileInfo) {
		return FilenameUtils.getBaseName(symbolFileInfo.getName()) + "." +
			makeCompressedExtension(FilenameUtils.getExtension(symbolFileInfo.getName()));
	}

	static String getCompressedFilename(String filename) {
		return FilenameUtils.getBaseName(filename) + "." +
			makeCompressedExtension(FilenameUtils.getExtension(filename));
	}

}
