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
package ghidra.app.util.opinion;

import java.io.*;
import java.util.*;

import org.apache.commons.io.FilenameUtils;

import db.DBConstants;
import db.DBHandle;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.framework.store.db.PackedDatabase;
import ghidra.framework.store.local.ItemSerializer;
import ghidra.program.database.DataTypeArchiveContentHandler;
import ghidra.program.database.DataTypeArchiveDB;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.program.model.listing.DataTypeArchive;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

/**
 * Loads a packed Ghidra data type archive.
 */
public class GdtLoader implements Loader {

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram) {
		return Collections.emptyList();
	}

	@Override
	public LoadResults<? extends DomainObject> load(ByteProvider provider, String filename,
			Project project, String projectFolderPath, LoadSpec loadSpec, List<Option> options,
			MessageLog messageLog, Object consumer, TaskMonitor monitor) throws IOException,
			CancelledException, VersionException {

		DataTypeArchive dtArchive =
			loadPackedProgramDatabase(provider, filename, consumer, monitor);
		return new LoadResults<>(dtArchive, filename, projectFolderPath);
	}

	private DataTypeArchive loadPackedProgramDatabase(ByteProvider provider, String programName,
			Object consumer, TaskMonitor monitor)
			throws IOException, CancelledException, VersionException, LanguageNotFoundException {
		DataTypeArchive dtArchive;
		File file = provider.getFile();
		File tmpFile = null;
		if (file == null) {
			file = tmpFile = createTmpFile(provider, monitor);
		}

		try {
			PackedDatabase packedDatabase = PackedDatabase.getPackedDatabase(file, true, monitor);
			boolean success = false;
			DBHandle dbh = null;
			try {
				if (!DataTypeArchiveContentHandler.DATA_TYPE_ARCHIVE_CONTENT_TYPE.equals(
					packedDatabase.getContentType())) {
					throw new IOException("File imported is not a Program: " + programName);
				}

				monitor.setMessage("Restoring " + provider.getName());

				dbh = packedDatabase.open(monitor);
				dtArchive = new DataTypeArchiveDB(dbh, DBConstants.UPGRADE, monitor, consumer);
				success = true;
			}
			finally {
				if (!success) {
					if (dbh != null) {
						dbh.close(); // also disposes packed database object
					}
					else {
						packedDatabase.dispose();
					}
				}
			}
			return dtArchive;
		}
		finally {
			if (tmpFile != null) {
				tmpFile.delete();
			}
		}
	}

	@Override
	public void loadInto(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			MessageLog messageLog, Program program, TaskMonitor monitor)
			throws IOException, LoadException, CancelledException {
		throw new LoadException("Cannot add GDT to program");
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
		if (options != null && options.size() > 0) {
			return "GDTLoader takes no options";
		}
		return null;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		if (isGDTFile(provider)) {
			loadSpecs.add(new LoadSpec(this, 0, false));
		}
		return loadSpecs;
	}

	@Override
	public String getPreferredFileName(ByteProvider provider) {
		return FilenameUtils.removeExtension(provider.getName());
	}

	private static File createTmpFile(ByteProvider provider, TaskMonitor monitor)
			throws IOException {
		File tmpFile = Application.createTempFile("ghidra_gdt_loader", null);
		try (InputStream is = provider.getInputStream(0);
				FileOutputStream fos = new FileOutputStream(tmpFile)) {
			FileUtilities.copyStreamToStream(is, fos, monitor);
		}
		return tmpFile;
	}

	private static boolean isGDTFile(ByteProvider provider) {
		if (!provider.getName().toLowerCase().endsWith(FileDataTypeManager.SUFFIX)) {
			return false;
		}
		boolean isGDT = false;
		try (InputStream inputStream = provider.getInputStream(0)) {
			isGDT = ItemSerializer.isPackedFile(inputStream);
		}
		catch (IOException e) {
			// ignore
		}
		return isGDT;
	}

	@Override
	public String getName() {
		return "Ghidra Data Type Archive Format";
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 0;
	}

}
