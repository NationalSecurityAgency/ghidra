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

import java.io.File;
import java.io.IOException;
import java.util.*;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.*;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.macho.MachException;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.bin.format.macho.commands.*;
import ghidra.app.util.bin.format.macho.dyld.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.DyldCacheLoader;
import ghidra.app.util.opinion.MachoLoader;
import ghidra.framework.options.Options;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * An analyzer that creates functions at addresses defined by the Mach-O LC_FUNCTION_STARTS 
 * load command.
 * <p>
 * NOTE: It's been observed that not all reported function starts are indeed real functions, so
 * this analyzer runs with a lower priority so it doesn't create functions where it shouldn't
 * (like on a switch table that Ghidra discovers in an early stage of analysis).
 */
public class MachoFunctionStartsAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "Mach-O Function Starts";
	private static final String DESCRIPTION =
		"An analyzer for discovering functions via the Mach-O LC_FUNCTION_STARTS load command";

	private static String OPTION_NAME_BOOKMARKS_NEW = "Bookmark new functions";
	private static String OPTION_DESC_BOOKMARKS_NEW =
		"Create a bookmark for each function sucessfully created by this analyzer";
	private static boolean OPTION_DEFAULT_BOOKMARKS_NEW = false;

	private static String OPTION_NAME_BOOKMARKS_FAILED = "Bookmark failed functions";
	private static String OPTION_DESC_BOOKMARKS_FAILED =
		"Create a bookmark for each function that this analyzer failed to create";
	private static boolean OPTION_DEFAULT_BOOKMARKS_FAILED = false;

	private static String OPTION_NAME_BOOKMARKS_SKIPPED = "Bookmark skipped functions";
	private static String OPTION_DESC_BOOKMARKS_SKIPPED =
		"Create a bookmark for each function that this analyzer skipped";
	private static boolean OPTION_DEFAULT_BOOKMARKS_SKIPPED = false;

	private static String OPTION_NAME_USE_PSEUDO = "Use PseudoDisassembler";
	private static String OPTION_DESC_USE_PSEUDO =
		"Use the PseudoDisassembler to evaluate function start addresses (disable to troubleshoot)";
	private static boolean OPTION_DEFAULT_USE_PSEUDO = true;

	private boolean isDyld;
	private boolean createBookmarksNew = OPTION_DEFAULT_BOOKMARKS_NEW;
	private boolean createBookmarksFailed = OPTION_DEFAULT_BOOKMARKS_FAILED;
	private boolean createBookmarksSkipped = OPTION_DEFAULT_BOOKMARKS_SKIPPED;
	private boolean usePseudoDisassembler = OPTION_DEFAULT_USE_PSEUDO;

	/**
	 * Creates a new {@link MachoFunctionStartsAnalyzer} 
	 */
	public MachoFunctionStartsAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setDefaultEnablement(true);

		// Some function starts have been observed to not be real functions.  This analyzer should
		// run later so it doesn't try to create functions where it shouldn't
		setPriority(AnalysisPriority.FUNCTION_ID_ANALYSIS.after());
	}

	@Override
	public boolean canAnalyze(Program program) {
		Options options = program.getOptions(Program.PROGRAM_INFO);
		String format = options.getString("Executable Format", null);
		isDyld = DyldCacheLoader.DYLD_CACHE_NAME.equals(format);
		return isDyld || MachoLoader.MACH_O_NAME.equals(format);
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_NAME_BOOKMARKS_NEW, OPTION_DEFAULT_BOOKMARKS_NEW, null,
			OPTION_DESC_BOOKMARKS_NEW);
		options.registerOption(OPTION_NAME_BOOKMARKS_FAILED, OPTION_DEFAULT_BOOKMARKS_FAILED, null,
			OPTION_DESC_BOOKMARKS_FAILED);
		options.registerOption(OPTION_NAME_BOOKMARKS_SKIPPED, OPTION_DEFAULT_BOOKMARKS_SKIPPED,
			null, OPTION_DESC_BOOKMARKS_SKIPPED);
		options.registerOption(OPTION_NAME_USE_PSEUDO, OPTION_DEFAULT_USE_PSEUDO, null,
			OPTION_DESC_USE_PSEUDO);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		createBookmarksNew =
			options.getBoolean(OPTION_NAME_BOOKMARKS_NEW, OPTION_DEFAULT_BOOKMARKS_NEW);
		createBookmarksFailed =
			options.getBoolean(OPTION_NAME_BOOKMARKS_FAILED, OPTION_DEFAULT_BOOKMARKS_FAILED);
		createBookmarksSkipped =
			options.getBoolean(OPTION_NAME_BOOKMARKS_SKIPPED, OPTION_DEFAULT_BOOKMARKS_SKIPPED);
		usePseudoDisassembler =
			options.getBoolean(OPTION_NAME_USE_PSEUDO, OPTION_DEFAULT_USE_PSEUDO);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		List<ByteProvider> providers = new ArrayList<>();
		for (FileBytes fileBytes : program.getMemory().getAllFileBytes()) {
			providers.add(new FileBytesProvider(fileBytes));
		}
		try {
			if (isDyld) {
				analyzeDyldCacheFunctionStarts(program, providers, set, monitor, log);
			}
			else {
				analyzeMachoFunctionStarts(program, providers.get(0), set, monitor, log);
			}
		}
		catch (Exception e) {
			return false;
		}
		finally {
			for (ByteProvider provider : providers) {
				try {
					provider.close();
				}
				catch (IOException e) {
					// Do nothing
				}
			}
		}

		return true;
	}
	
	/**
	 * Finds and creates new functions in the given Mach-O using the LC_FUNCTION_STARTS load command
	 * 
	 * @param program The {@link Program}
	 * @param provider The {@link ByteProvider} that contains the original file bytes
	 * @param set The set of addresses to find new functions at
	 * @param monitor A cancellable monitor
	 * @param log The log
	 * @throws MachException If there was an issue parsing the headers
	 * @throws IOException If an IO-related issue occurred
	 * @throws CancelledException If the user cancelled
	 */
	private void analyzeMachoFunctionStarts(Program program, ByteProvider provider,
			AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws MachException, IOException, CancelledException {
		MachHeader header = new MachHeader(provider);
		header.parse();
		monitor.setIndeterminate(true);
		monitor.setMessage("Analyzing function starts...");
		analyzeFunctionStarts(program, header, provider, set, monitor);
	}

	/**
	 * Finds and creates new functions in the given DyldCache using the LC_FUNCTION_STARTS load 
	 * command from each Mach-O header
	 * 
	 * @param program The {@link Program}
	 * @param providers A {@link List} of {@link ByteProvider}s that contains the original file 
	 *   bytes
	 * @param set The set of addresses to find new functions at
	 * @param monitor A cancellable monitor
	 * @param log The log
	 * @throws MachException If there was an issue parsing the headers
	 * @throws IOException If an IO-related issue occurred
	 * @throws CancelledException If the user cancelled
	 */
	private void analyzeDyldCacheFunctionStarts(Program program, List<ByteProvider> providers,
			AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws MachException, IOException, CancelledException {
		Map<DyldCacheHeader, ByteProvider> providerMap = new HashMap<>();

		// Parse all DYLD Cache headers.  There could be more that one if the DYLD Cache is "split".
		for (ByteProvider provider : providers) {
			DyldCacheHeader header = new DyldCacheHeader(new BinaryReader(provider, true));
			header.parseFromFile(false, log, monitor);
			providerMap.put(header, provider);
		}

		// Process each Mach-O header found in each DYLD Cache header
		for (DyldCacheHeader dyldCacheHeader : providerMap.keySet()) {
			List<DyldCacheImage> mappedImages = dyldCacheHeader.getMappedImages();
			monitor.initialize(mappedImages.size());
			for (DyldCacheImage mappedImage : mappedImages) {
				String name = new File(mappedImage.getPath()).getName();
				monitor.checkCancelled();
				monitor.setMessage("Analyzing function starts for " + name + "...");
				monitor.incrementProgress(1);

				// Parse Mach-O header
				MachHeader machoHeader = new MachHeader(providerMap.get(dyldCacheHeader),
					mappedImage.getAddress() - dyldCacheHeader.getBaseAddress(), false);
				machoHeader.parse();

				// The list of function starts should always be in a __LINKEDIT segment.
				// If the DYLD Cache is "split", a Mach-O's __LINKEDIT segment may live in a
				// different provider.
				SegmentCommand linkEdit = machoHeader.getSegment(SegmentNames.SEG_LINKEDIT);
				if (linkEdit != null) {
					boolean foundLinkEdit = false;
					for (DyldCacheHeader header : providerMap.keySet()) {
						for (DyldCacheMappingInfo mappingInfo : header.getMappingInfos()) {
							if (mappingInfo.contains(linkEdit.getVMaddress())) {
								analyzeFunctionStarts(program, machoHeader, providerMap.get(header),
									set, monitor);
								foundLinkEdit = true;
								break;
							}
						}
						if (foundLinkEdit) {
							break;
						}
					}
				}
				else {
					log.appendMsg(
						"Failed to find " + SegmentNames.SEG_LINKEDIT + " segment for " + name);
				}
			}
		}
	}

	/**
	 * Finds and creates new functions using the LC_FUNCTION_STARTS load command
	 * 
	 * @param program The {@link Program}
	 * @param header The {@link MachHeader} that contains the LC_FUNCTION_STARTS load command
	 * @param provider The {@link ByteProvider} that contains the LC_FUNCTION_STARTS data
	 * @param set The set of addresses to find new functions at
	 * @param monitor A cancellable monitor
	 * @throws CancelledException If the user cancelled
	 */
	private void analyzeFunctionStarts(Program program, MachHeader header, ByteProvider provider,
			AddressSetView set, TaskMonitor monitor) throws IOException, CancelledException {
		FunctionManager functionMgr = program.getFunctionManager();
		Listing listing = program.getListing();
		PseudoDisassembler pdis = new PseudoDisassembler(program);
		Disassembler dis = Disassembler.getDisassembler(program, monitor, null);
		AutoAnalysisManager analysisMgr = AutoAnalysisManager.getAnalysisManager(program);

		// Function start values are offsets from start of text segment
		SegmentCommand textSegment = header.getSegment(SegmentNames.SEG_TEXT);
		if (textSegment == null) {
			return;
		}

		// Determine which function start addresses need a new function created on them
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		Address textSegmentAddr = space.getAddress(textSegment.getVMaddress());
		List<FunctionStartsCommand> commands = header.getLoadCommands(FunctionStartsCommand.class);
		for (FunctionStartsCommand cmd : commands) {
			for (Address addr : cmd.findFunctionStartAddrs(provider, textSegmentAddr)) {
				monitor.checkCancelled();
				if (!set.contains(textSegmentAddr)) {
					continue;
				}

				// Check for conditions to skip creating a function at the function start address
				String skipMessage = null;
				if (listing.getDataAt(addr) != null && !listing.isUndefined(addr, addr)) {
					skipMessage = "Skipped Existing Data"; // possible switch data
				}
				else if (functionMgr.getFunctionAt(addr) != null) {
					skipMessage = "Skipped Existing Function";
				}
				else if (usePseudoDisassembler) {
					try {
						final String UDF = "UDF";
						if (pdis.disassemble(addr).getMnemonicString().equalsIgnoreCase(UDF)) {
							skipMessage = "Skipped \"" + UDF + "\" Instruction";
						}
						else if (!pdis.isValidSubroutine(addr, true, false)) {
							skipMessage = "Skipped Invalid Subroutine";
						}
					}
					catch (Exception e) {
						// ignore
					}
				}
				if (skipMessage != null) {
					if (createBookmarksSkipped) {
						setBookmark(program, addr,  skipMessage);

					}
					continue;
				}

				// Disassemble at the function start address
				AddressSet disassembledSet = dis.disassemble(new AddressSet(addr), null, true);
				analysisMgr.codeDefined(disassembledSet);

				// Create function at the function start address
				CreateFunctionCmd fCommand = new CreateFunctionCmd(addr);
				if (fCommand.applyTo(program, monitor)) {
					if (createBookmarksNew) {
						setBookmark(program, addr, "New Function");

					}
				}
				else {
					// Couldn't create function
					if (createBookmarksFailed) {
						setBookmark(program, addr, "Failed Function");
					}
				}
			}
		}
	}
	
	/**
	 * Creates a standard bookmark pertaining to this analyzer
	 * 
	 * @param program The {@link Program}
	 * @param addr The {@link Address} to create a new bookmark at
	 * @param message The bookmark's message
	 */
	private void setBookmark(Program program, Address addr, String message) {
		BookmarkManager bookmarkMgr = program.getBookmarkManager();
		bookmarkMgr.setBookmark(addr, BookmarkType.ANALYSIS, message, "LC_FUNCTION_STARTS");
	}
}
