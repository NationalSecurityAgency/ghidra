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
package ghidra.app.plugin.core.debug.utils;

import java.io.*;
import java.util.*;

import org.apache.commons.io.FilenameUtils;

import db.DBHandle;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.*;
import ghidra.framework.Application;
import ghidra.framework.data.OpenMode;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.db.PackedDatabase;
import ghidra.framework.store.local.ItemSerializer;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.program.model.listing.Program;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceContentHandler;
import ghidra.trace.model.Trace;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

/**
 * Loads a packed Ghidra Trace file.
 */
public class GztLoader implements Loader {

	public final static String GZT_NAME = "GZT Input Format";

	@Override
	public LoaderTier getTier() {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 0;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		if (options != null && options.size() > 0) {
			return "GztLoader takes no options";
		}
		return null;
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
		return List.of();
	}

	@Override
	public LoadResults<? extends DomainObject> load(ImporterSettings settings)
			throws IOException, CancelledException, VersionException {

		Trace trace = loadPackedTraceDatabase(settings.provider(), settings.importName(),
			settings.consumer(), settings.monitor());
		return new LoadResults<>(new Loaded<>(trace, settings));
	}

	private Trace loadPackedTraceDatabase(ByteProvider provider, String traceName,
			Object consumer, TaskMonitor monitor)
			throws IOException, CancelledException, VersionException, LanguageNotFoundException {
		Trace trace;
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
				if (!DBTraceContentHandler.TRACE_CONTENT_TYPE
						.equals(packedDatabase.getContentType())) {
					throw new IOException("File imported is not a Trace: " + traceName);
				}

				monitor.setMessage("Restoring " + provider.getName());

				dbh = packedDatabase.open(monitor);

				trace = new DBTrace(dbh, OpenMode.UPGRADE, monitor, consumer);
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
			return trace;
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
		throw new LoadException("Cannot add GZT to program");
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		if (isGztFile(provider)) {
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
		File tmpFile = Application.createTempFile("ghidra_gzt_loader", null);
		try (InputStream is = provider.getInputStream(0);
				FileOutputStream fos = new FileOutputStream(tmpFile)) {
			FileUtilities.copyStreamToStream(is, fos, monitor);
		}
		return tmpFile;
	}

	private static boolean isGztFile(ByteProvider provider) {
		if (!provider.getName().toLowerCase().endsWith(".gzt")) {
			return false;
		}
		boolean isGZT = false;
		try (InputStream inputStream = provider.getInputStream(0)) {
			isGZT = ItemSerializer.isPackedFile(inputStream);
		}
		catch (IOException e) {
			// ignore
		}
		return isGZT;
	}

	@Override
	public String getName() {
		return GZT_NAME;
	}
}
