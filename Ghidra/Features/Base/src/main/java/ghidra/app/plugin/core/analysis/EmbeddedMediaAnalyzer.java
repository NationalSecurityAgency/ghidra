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
package ghidra.app.plugin.core.analysis;

import java.util.*;

import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class EmbeddedMediaAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "Embedded Media";
	private static final String DESCRIPTION =
		"Finds and tries to apply embedded media data types (ie png, gif, jpeg, wav) in current program.";

	private static final String OPTION_NAME_CREATE_BOOKMARKS = "Create Analysis Bookmarks";
	private static final String OPTION_DESCRIPTION_CREATE_BOOKMARKS =
		"If checked, an analysis bookmark will be created at each location where embedded media data is identified.";
	private static final boolean OPTION_DEFAULT_CREATE_BOOKMARKS_ENABLED = true;

	private boolean createBookmarksEnabled = OPTION_DEFAULT_CREATE_BOOKMARKS_ENABLED;

	public EmbeddedMediaAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.BLOCK_ANALYSIS);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		Memory memory = program.getMemory();
		AddressSetView initializedAddressSet = memory.getLoadedAndInitializedAddressSet();
		AddressSet initialedSearchSet = set.intersect(initializedAddressSet);

		List<Address> foundMedia = new ArrayList<>();

		foundMedia = scanForMedia(program, new GifDataType(), "GIF 87", GifDataType.MAGIC_87,
			GifDataType.GIFMASK, initialedSearchSet, memory, monitor);

		foundMedia.addAll(scanForMedia(program, new GifDataType(), "GIF 89", GifDataType.MAGIC_89,
			GifDataType.GIFMASK, initialedSearchSet, memory, monitor));

		foundMedia.addAll(scanForMedia(program, new PngDataType(), "PNG", PngDataType.MAGIC,
			PngDataType.MASK, initialedSearchSet, memory, monitor));

		foundMedia.addAll(scanForMedia(program, new JPEGDataType(), "JPEG", JPEGDataType.MAGIC,
			JPEGDataType.MAGIC_MASK, initialedSearchSet, memory, monitor));

		foundMedia.addAll(scanForMedia(program, new WAVEDataType(), "WAVE", WAVEDataType.MAGIC,
			WAVEDataType.MAGIC_MASK, initialedSearchSet, memory, monitor));

		foundMedia.addAll(scanForMedia(program, new AUDataType(), "AU", AUDataType.MAGIC,
			AUDataType.MAGIC_MASK, initialedSearchSet, memory, monitor));

		foundMedia.addAll(scanForMedia(program, new AIFFDataType(), "AIFF", AIFFDataType.MAGIC,
			AIFFDataType.MAGIC_MASK, initialedSearchSet, memory, monitor));

		return true;
	}

	private List<Address> scanForMedia(Program program, DataType dt, String mediaName,
			byte[] mediaBytes, byte[] mask, AddressSetView addresses, Memory memory,
			TaskMonitor monitor) {

		monitor.setMessage("Scanning for " + mediaName + " Embedded Media");
		monitor.initialize(addresses.getNumAddresses());

		List<Address> foundMediaAddresses = new ArrayList<>();

		Iterator<AddressRange> iterator = addresses.iterator();
		while (iterator.hasNext()) {
			if (monitor.isCancelled()) {
				return foundMediaAddresses;
			}

			AddressRange range = iterator.next();
			Address start = range.getMinAddress();
			Address end = range.getMaxAddress();

			Address found = memory.findBytes(start, end, mediaBytes, mask, true, monitor);
			while (found != null && !monitor.isCancelled()) {
				//See if it is already an applied media data type
				Data data = program.getListing().getDefinedDataAt(found);
				int skipLen = 1;
				if (data == null) {
					try {
						CreateDataCmd cmd = new CreateDataCmd(found, dt);
						if (cmd.applyTo(program)) {
							if (createBookmarksEnabled) {
								program.getBookmarkManager().setBookmark(found,
									BookmarkType.ANALYSIS, "Embedded Media",
									"Found " + mediaName + " Embedded Media");
							}
							foundMediaAddresses.add(found);
							//have to get the actual applied data to find the actual length to skip because until then it can't compute the length due to the data type being dynamic
							skipLen = program.getListing().getDataAt(found).getLength();
						}
					}
					//If media does not apply correctly then it is not really a that media data type or there is other data in the way
					catch (Exception e) {
						// Not a valid embedded media or no room to apply it so just ignore it and skip it
					}
				}
				// skip either the valid data that was found or skip one byte
				// then do the next search
				start = found.add(skipLen);
				found = memory.findBytes(start, end, mediaBytes, mask, true, monitor);
			}
		}

		return foundMediaAddresses;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_NAME_CREATE_BOOKMARKS, createBookmarksEnabled, null,
			OPTION_DESCRIPTION_CREATE_BOOKMARKS);

	}

	@Override
	public void optionsChanged(Options options, Program program) {
		createBookmarksEnabled =
			options.getBoolean(OPTION_NAME_CREATE_BOOKMARKS, createBookmarksEnabled);
	}
}
