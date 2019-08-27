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
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.*;
import ghidra.framework.store.local.ItemSerializer;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.listing.DataTypeArchive;
import ghidra.program.model.listing.Program;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

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
	public List<DomainObject> load(ByteProvider provider, String filename,
			DomainFolder programFolder, LoadSpec loadSpec, List<Option> options,
			MessageLog messageLog, Object consumer, TaskMonitor monitor) throws IOException,
			CancelledException, DuplicateNameException, InvalidNameException, VersionException {

		DomainFile df = doImport(provider, filename, programFolder, monitor);

		monitor.setMessage("Opening " + filename);
		// Allow upgrade since imported project archives must always be upgraded
		DomainObject dobj = df.getDomainObject(consumer, true, false, monitor);
		if (!(dobj instanceof DataTypeArchive)) {
			if (dobj != null) {
				dobj.release(consumer);
				df.delete();
			}
			throw new IOException("File imported is not a Data Type Archive: " + filename);
		}

		List<DomainObject> results = new ArrayList<DomainObject>();
		results.add(dobj);
		return results;
	}

	private DomainFile doImport(ByteProvider provider, String filename,
			DomainFolder programFolder, TaskMonitor monitor)
			throws InvalidNameException, CancelledException, IOException {

		File file = provider.getFile();
		DomainFolder folder = programFolder;

		monitor.setMessage("Restoring " + file.getName());

		DomainFile df = folder.createFile(filename, file, monitor);

		return df;
	}

	@Override
	public boolean loadInto(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			MessageLog messageLog, Program program, TaskMonitor monitor)
			throws IOException, CancelledException {
		throw new UnsupportedOperationException("cannot add GDT to program");
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
