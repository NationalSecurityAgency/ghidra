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

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.framework.Application;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.local.ItemSerializer;
import ghidra.program.database.dtarchive.*;
import ghidra.program.model.dtarchive.ProjectDataTypeArchive;
import ghidra.program.model.lang.LanguageNotFoundException;
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
			DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
		return List.of();
	}

	@Override
	public LoadResults<? extends DomainObject> load(ImporterSettings settings)
			throws IOException, CancelledException, VersionException {

		ProjectDataTypeArchive dtArchive = loadPackedDtArchiveDatabase(settings.provider(),
			settings.importName(), settings.consumer(), settings.monitor());
		return new LoadResults<>(new Loaded<>(dtArchive, settings));
	}

	private ProjectDataTypeArchive loadPackedDtArchiveDatabase(ByteProvider provider,
			String archiveName,
			Object consumer, TaskMonitor monitor)
			throws IOException, CancelledException, VersionException, LanguageNotFoundException {
		ProjectDtArchiveDB dtArchive;
		File file = provider.getFile();
		File tmpFile = null;
		if (file == null) {
			file = tmpFile = createTmpFile(provider, monitor);
		}

		try {
			return DataTypeArchiveFactory.importProjectArchive(file, archiveName, consumer,
				monitor);
		}
		finally {
			if (tmpFile != null) {
				tmpFile.delete();
			}
		}
	}

	@Override
	public void loadInto(Program program, ImporterSettings settings)
			throws IOException, LoadException, CancelledException {
		throw new LoadException("Cannot add GDT to program");
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
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
		if (!provider.getName().toLowerCase().endsWith(FileDtArchiveDB.SUFFIX)) {
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
