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

import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.util.bytesearch.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class EmbeddedMediaAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "Embedded Media";
	private static final String DESCRIPTION =
		"Finds embedded media data types (ie png, gif, jpeg, wav)";

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
		AddressSetView validMemorySet = memory.getLoadedAndInitializedAddressSet();
		AddressSetView searchSet = set.intersect(validMemorySet);
		if (searchSet.isEmpty()) {
			return false;  // no valid addresses to search
		}

		MemoryBytePatternSearcher searcher = new MemoryBytePatternSearcher("Embedded Media");

		List<Address> foundMedia = new ArrayList<>();

		addByteSearchPattern(searcher, program, foundMedia, new GifDataType(), "GIF 87",
			GifDataType.MAGIC_87, GifDataType.GIFMASK);

		addByteSearchPattern(searcher, program, foundMedia, new GifDataType(), "GIF 89",
			GifDataType.MAGIC_89, GifDataType.GIFMASK);

		addByteSearchPattern(searcher, program, foundMedia, new PngDataType(), "PNG",
			PngDataType.MAGIC, PngDataType.MASK);

		addByteSearchPattern(searcher, program, foundMedia, new JPEGDataType(), "JPEG",
			JPEGDataType.MAGIC, JPEGDataType.MAGIC_MASK);

		addByteSearchPattern(searcher, program, foundMedia, new WAVEDataType(), "WAVE",
			WAVEDataType.MAGIC, WAVEDataType.MAGIC_MASK);

		addByteSearchPattern(searcher, program, foundMedia, new AUDataType(), "AU",
			AUDataType.MAGIC, AUDataType.MAGIC_MASK);

		addByteSearchPattern(searcher, program, foundMedia, new AIFFDataType(), "AIFF",
			AIFFDataType.MAGIC, AIFFDataType.MAGIC_MASK);

		searcher.search(program, searchSet, monitor);

		return foundMedia.size() > 0;
	}

	private void addByteSearchPattern(MemoryBytePatternSearcher searcher, Program program,
			List<Address> foundMedia, DataType mediaDT, String mediaName, byte[] bytes,
			byte[] mask) {
		if (bytes == null) {
			return;
		}

		GenericMatchAction<DataType> action = new GenericMatchAction<DataType>(mediaDT) {
			@Override
			public void apply(Program prog, Address addr, Match match) {
				//See if it is already an applied media data type
				if (!program.getListing().isUndefined(addr, addr)) {
					return;
				}

				try {
					CreateDataCmd cmd = new CreateDataCmd(addr, mediaDT);
					if (cmd.applyTo(program)) {
						if (createBookmarksEnabled) {
							program.getBookmarkManager().setBookmark(addr, BookmarkType.ANALYSIS,
								"Embedded Media", "Found " + mediaName + " Embedded Media");
						}
						foundMedia.add(addr);
					}
				}
				//If media does not apply correctly then it is not really a that media data type or there is other data in the way
				catch (Exception e) {
					// Not a valid embedded media or no room to apply it so just ignore it and skip it
				}
			}
		};

		GenericByteSequencePattern<DataType> genericByteMatchPattern =
			new GenericByteSequencePattern<DataType>(bytes, mask, action);

		searcher.addPattern(genericByteMatchPattern);
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
