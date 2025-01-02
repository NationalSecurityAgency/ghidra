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
package ghidra.app.util.pdb.pdbapplicator;

import java.util.*;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.Module;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.store.LockException;
import ghidra.program.database.sourcemap.SourceFile;
import ghidra.program.database.sourcemap.SourceFileIdType;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.*;
import ghidra.program.model.sourcemap.SourceFileManager;
import ghidra.util.Msg;
import ghidra.util.SourceFileUtils;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Helper class to PdbApplicator for applying source line information
 */
public class PdbSourceLinesApplicator {

	private DefaultPdbApplicator applicator;
	private AbstractPdb pdb;
	private Program program;
	private MessageLog log;

	private Map<Address, Integer> functionLengthByAddress;

	private SourceFileManager manager;

	//==============================================================================================
	/**
	 * Constructor for PdbSourceLinesApplicator
	 * @param applicator the PdbApplicator that we are helping
	 */
	public PdbSourceLinesApplicator(DefaultPdbApplicator applicator) {
		Objects.requireNonNull(applicator, "applicator cannot be null");
		this.applicator = applicator;
		this.program = applicator.getProgram();
		Objects.requireNonNull(program, "program cannot be null");
		this.pdb = applicator.getPdb();
		Objects.requireNonNull(pdb, "pdb cannot be null");
		this.log = applicator.getMessageLog();

		functionLengthByAddress = new HashMap<>();

		manager = program.getSourceFileManager();
	}

	//==============================================================================================
	/**
	 * When determined elsewhere, and before {@code process()} is called, this method should
	 * be used to populate the lengths of functions in to this lines applier.  If not done, then
	 * some source line code lengths might not be correct
	 * @param address the address
	 * @param length the function length
	 */
	public void setFunctionLength(Address address, int length) {
		functionLengthByAddress.put(address, length);
	}

	//==============================================================================================
	/**
	 * Process all Module line information
	 * @param monitor the task monitor
	 * @throws CancelledException upon user cancellation
	 */
	public void process(TaskMonitor monitor) throws CancelledException {
		PdbDebugInfo debugInfo = pdb.getDebugInfo();
		if (debugInfo == null) {
			Msg.info(this, "PDB: Missing DebugInfo - cannot process line numbers.");
			return;
		}
		if (!program.hasExclusiveAccess()) {
			Msg.showWarn(this, null, "Cannot Apply SourceMap Information",
				"Exclusive access to the program is required to apply source map information");
			return;
		}

		// Not processing user defined "Types" source information.  TODO: ???

		int numModules = debugInfo.getNumModules();
		monitor.initialize(numModules);
		monitor.setMessage("PDB: Importing module function source line information...");
		for (int num = 1; num <= numModules; num++) {
			monitor.checkCancelled();
			Module module = debugInfo.getModule(num);
			processC11Lines(module);
			processC13Sections(module);
			monitor.incrementProgress(1);
		}
	}

	//==============================================================================================
	// Suppress: for moduleInfo due to commented out call to processC11Line.  Remove suppress when
	//  no longer commented out.
	@SuppressWarnings("unused")
	private void processC11Lines(Module module)
			throws CancelledException {
		ModuleInformation moduleInfo = module.getModuleInformation();
		try {
			C11Lines c11Lines = module.getLineInformation();
			if (c11Lines != null) {
				// TODO: Figure out how to process and what to do with inline information.  When
				//  ready, uncomment the following code
//				processC11Line(moduleInfo, c11Lines);
				// TODO: remove this and underlying Metrics logic once we have a viable processing
				//  technique for inlinee lines
				applicator.getPdbApplicatorMetrics().witnessC11Lines();
			}
		}
		catch (PdbException e) {
			log.appendMsg("PDB: Failed to process C11Lines due to " + e.getMessage());
			return;
		}
	}

	// Suppress: for not being used and for unfinished implementation with unused variables
	@SuppressWarnings("unused")
	// TODO: Figure out how to process and what to do with inline information.  When
	//  ready, uncomment the following code
	private void processC11Line(ModuleInformation moduleInfo,
			C11Lines c11Lines) {
		Msg.info(this, "PDB: Unimplemented... unable to process C11 Lines");
		// TODO: See C11Lines dump method for indications of how we might process
		int cFile = c11Lines.getNumFiles();
		int cSet = c11Lines.getNumSegments();
		List<Integer> baseSrcFile = c11Lines.getBaseSrcFiles();
		List<C11LinesStartEnd> startEnd = c11Lines.getStartEnd();
		List<Integer> seg = c11Lines.getSegments();
		List<Integer> ccSegs = c11Lines.getPerFileNumSegments();
		List<List<Integer>> baseSrcLines = c11Lines.getPerFileBaseSrcLines();
		List<List<C11LinesStartEnd>> startEnds = c11Lines.getPerFileStartEndRecords();
		List<String> names = c11Lines.getFileNames();
		List<List<Integer>> segmentNumbers = c11Lines.getPerFileSegmentNumbers();
		List<List<List<Long>>> offsets = c11Lines.getPerFilePerSegmentOffsets();
		List<List<List<Integer>>> lineNumbers = c11Lines.getPerFilePerSegmentLineNumbers();
		// do something
	}

	//==============================================================================================
	private void processC13Sections(Module module)
			throws CancelledException {

		ModuleInformation moduleInfo = module.getModuleInformation();

		C13SectionIterator<FileChecksumsC13Section> c13FileChecksumIterator;
		C13SectionIterator<LinesC13Section> linesIterator;
		C13SectionIterator<IlLinesC13Section> ilLinesIterator;
		C13SectionIterator<InlineeLinesC13Section> inlineeLinesIterator;
		try {
			c13FileChecksumIterator =
				module.getC13SectionFilteredIterator(FileChecksumsC13Section.class);
			linesIterator = module.getC13SectionFilteredIterator(LinesC13Section.class);
			ilLinesIterator = module.getC13SectionFilteredIterator(IlLinesC13Section.class);
			inlineeLinesIterator =
				module.getC13SectionFilteredIterator(InlineeLinesC13Section.class);
		}
		catch (PdbException e) {
			log.appendMsg("PDB: Failed to process C13Sections due to " + e.getMessage());
			return;
		}

		// Must do file checksums first, as they have the file information for the source lines
		// Make sure there is one and only one
		FileChecksumsC13Section fileChecksumsSection = null;
		while (c13FileChecksumIterator.hasNext()) {
			pdb.checkCancelled();
			FileChecksumsC13Section section = c13FileChecksumIterator.next();
			if (fileChecksumsSection != null) {
				Msg.warn(this, "More than on FileChecksumC13Section found in module " +
					moduleInfo.getModuleName());
				break;
			}
			fileChecksumsSection = section;
		}
		if (fileChecksumsSection == null) {
			// No information for this module
			return;
		}

		// Process lines, ilLines, and inlineeLines
		while (linesIterator.hasNext()) {
			pdb.checkCancelled();
			LinesC13Section linesSection = linesIterator.next();
			processC13FileRecords(moduleInfo, fileChecksumsSection, linesSection, false);
		}
		while (ilLinesIterator.hasNext()) {
			pdb.checkCancelled();
			IlLinesC13Section ilLinesSection = ilLinesIterator.next();
			processC13FileRecords(moduleInfo, fileChecksumsSection, ilLinesSection, true);
		}
		// TODO: Figure out how to process and what to do with inline information.  When
		//  ready, uncomment the following code
//		while (inlineeLinesIterator.hasNext()) {
//			monitor.checkCancelled();
//			InlineeLinesC13Section inlineeSection = inlineeLinesIterator.next();
//			processC13InlineeLines(moduleInfo, fileChecksumsSection, inlineeSection);
//		}
		// TODO: remove this and underlying Metrics logic once we have a viable processing
		//  technique for inlinee lines
		if (inlineeLinesIterator.hasNext()) {
			applicator.getPdbApplicatorMetrics().witnessC13InlineeLines();
		}
	}

	//==============================================================================================
	private void processC13FileRecords(ModuleInformation moduleInfo,
			FileChecksumsC13Section fileChecksumsC13Section, AbstractLinesC13Section c13Lines,
			boolean isIlLines)
			throws CancelledException {

		// Something else to look into: ModuleInformation600 version has more fields that we do
		//  not know their usefulness at this time.  These are:
		// String moduleName = moduleInfo.getModuleName();
		// String objectFileName = moduleInfo.getObjectFileName();
		List<C13FileRecord> fileRecords = c13Lines.getFileRecords();

		long offCon = c13Lines.getOffCon();
		int segCon = c13Lines.getSegCon();
		// Currently not using getFlags() and getLenCon()
		for (C13FileRecord fileRecord : fileRecords) {
			pdb.checkCancelled();
			int fileId = fileRecord.getFileId();
			SourceFile sourceFile = getSourceFile(fileChecksumsC13Section, fileId);

			// Everything we've see to this point shows that the address come in an increasing,
			//  but non-strictly increasing order.  Also, there is not a field to designate the
			//  number of bytes of memory that pertain to each line record, but everything we've
			//  seen seems to indicate that we can do the difference between the record addresses
			//  to get the length needed.  However, the last record doesn't have a "next" record
			//  to do the difference with, but that is where function length comes into play.
			//  And if we work in reverse order (we do not care if the records are created and
			//  put into the DB in reverse order), then we can easily calculate the lengths.
			long lastValue = -1;
			Long numLines = fileRecord.getNLines();
			List<C13LineRecord> lineRecords = fileRecord.getLineRecords();
			for (int index = numLines.intValue() - 1; index >= 0; index--) {
				pdb.checkCancelled();
				C13LineRecord lineRecord = lineRecords.get(index);
				Long lineNumStart = lineRecord.getLineNumStart();
				// If we wanted the line end value, we could calculate it as:
				// Long lineNumEnd = lineNumStart + lineRecord.getDeltaLineEnd()
				long offset = lineRecord.getOffset();
				long actualOffset = offset + offCon;
				Address address = applicator.getAddress(segCon, actualOffset);
				if (lastValue == -1) {
					FunctionManager functionManager = program.getFunctionManager();
					Function function = functionManager.getFunctionContaining(address);
					if (function != null) {
						Address functionAddress = function.getEntryPoint();
						lastValue = functionLengthByAddress.getOrDefault(functionAddress, -1);
					}
					// If function was null, then lastValue stays -1 until overwritten
				}
				Long length = lastValue - offset;
				// TODO: remove  next line once we initialize an appropriate lastValue
				length = Long.max(length, 0); // last record gets length zero if lastValue was -1
				lastValue = offset;

				// Note: we are not currently using boolean isStatement = lineRecord.isStatement()

				// Note: we are not using this call, but users might be interested in the fact of
				// 0xfeefee and 0xf00f00.
				// lineRecord.isSpecialLine();

				// TODO: There might be something we can do with the boolean isIlLines
				//  Seems that the pdb.xml is not necessarily doing anything different

				applyRecord(sourceFile, address, lineNumStart.intValue(),
					length.intValue());

				// Note: We are not processing column records, but they are available.
			}
		}
	}

	//==============================================================================================
	// Suppress: for not being used and for unfinished implementation with unused variables
	@SuppressWarnings("unused")
	private void processC13InlineeLines(ModuleInformation moduleInfo,
			FileChecksumsC13Section fileChecksumsC13Section, InlineeLinesC13Section c13InlineeLines)
			throws CancelledException {

		// Something else to look into: ModuleInformation600 version has more fields that we do
		//  not know their usefulness at this time
		//String moduleName = moduleInfo.getModuleName();
		//String objectFileName = moduleInfo.getObjectFileName();
		List<C13InlineeSourceLine> inlineeLines = c13InlineeLines.getInlineeLines();

		for (C13InlineeSourceLine inlineeLine : inlineeLines) {
			pdb.checkCancelled();

			int fileId = inlineeLine.getFileId();
			SourceFile sourceFile = getSourceFile(fileChecksumsC13Section, fileId);

			Long inlinee = inlineeLine.getInlinee();
			RecordNumber recordNumber = RecordNumber.itemRecordNumber(inlinee.intValue());
			AbstractMsType type = applicator.getTypeRecord(recordNumber);
			//TODO: might want to create TypeAppliers for MemberFunctionIdMsType and
			// FunctionIdMsType and any of their derivatives and use them to do logic for the
			// types.
			if (type instanceof FunctionIdMsType functionId) {
				String name = functionId.getName();
				RecordNumber scopeIdRecordNumber = functionId.getScopeIdRecordNumber();
				AbstractMsType scope = applicator.getTypeRecord(scopeIdRecordNumber);
				// TODO: DO MORE WORK
			}
			else if (type instanceof MemberFunctionIdMsType memberFunctionId) {
				String name = memberFunctionId.getName();
				RecordNumber parentTypeRecordNumber = memberFunctionId.getParentTypeRecordNumber();
				AbstractMsType parent = applicator.getTypeRecord(parentTypeRecordNumber);
				// TODO: DO MORE WORK
			}
			else {
				// TODO: DO MORE WORK
			}

			long lineNum = inlineeLine.getSourceLineNum();

			if (inlineeLine instanceof C13ExtendedInlineeSourceLine extendedInlineeLine) {
				int numIds = extendedInlineeLine.getNumExtraFileIds();
				List<Integer> ids = extendedInlineeLine.getExtraFileIds();
				for (int id : ids) {
					SourceFile inlineeSourceFile = getSourceFile(fileChecksumsC13Section, id);
					// TODO: DO MORE WORK
				}
			}
		}
	}

	//==============================================================================================
	// Processing in the section is geared toward C13 records processing.  Have not evaluated its
	//  usefulness for C11 records
	/**
	 * Finds or creates a SourceFile for our checksum and file ID for C13 processing
	 * @param fileChecksums the set of FileChecksumC13Sections for this module
	 * @param fileId the file ID found in the source line records
	 * @return the source file
	 */
	private SourceFile getSourceFile(FileChecksumsC13Section fileChecksums, int fileId) {

		// Note: fileId is an offset into the checksum table, so we have them stored in a map.
		C13FileChecksum checksumInfo = fileChecksums.getFileChecksumByOffset(fileId);

		Long offsetFilename = checksumInfo.getOffsetFilename();
		String filename = pdb.getNameStringFromOffset(offsetFilename.intValue());
		SourceFileIdType idType = switch (checksumInfo.getChecksumTypeValue()) {
			case 0 -> SourceFileIdType.NONE;
			case 1 -> SourceFileIdType.MD5;
			case 2 -> SourceFileIdType.SHA1;
			case 3 -> SourceFileIdType.SHA256;
			default -> SourceFileIdType.UNKNOWN;
		};
		byte[] identifier = checksumInfo.getChecksumBytes();

		SourceFile sourceFile =
			SourceFileUtils.getSourceFileFromPathString(filename, idType, identifier);
		try {
			manager.addSourceFile(sourceFile);
		}
		catch (LockException e) {
			throw new AssertionError("LockException after exclusive access verified!");
		}
		return sourceFile;
	}

	//==============================================================================================
	private void applyRecord(SourceFile sourceFile, Address address, int start, int length) {
		// Need to use getCodeUnitContaining(address) instead of getCodeUnitAt(address) because
		//  there is a situation where the PDB associates a line number with the base part of an
		//  instructions instead of the prefix part, such as with MSFT tool-chain emits a
		//  "REP RET" (f3 c3) sequence, where the "REP" is an instruction prefix, in order to
		//  avoid a branch prediction penalty for AMD processors.  However, Microsoft associates
		//  the line number of the instruction with the address of the "RET" (c3) instead of with
		//  the address of the "REP" (f3) portion (beginning) of the instruction.
		CodeUnit cu = program.getListing().getCodeUnitContaining(address);
		if (cu == null) {
			log.appendMsg("PDB",
				"Skipping source map info (no code unit found at " + address + ")");
			return;
		}

		try {
			manager.addSourceMapEntry(sourceFile, start, address, length);
		}
		catch (LockException e) {
			throw new AssertException("LockException after exclusive access verified!");
		}
		catch (AddressOverflowException e) {
			log.appendMsg("PDB", "AddressOverflow for source map info: %s, %d, %s, %d"
					.formatted(sourceFile.getPath(), start, address.toString(), length));
		}
		catch (IllegalArgumentException e) {
			// thrown by SourceFileManager.addSourceMapEntry if the new entry conflicts
			// with an existing entry or if sourceFile is not associated with manager
			log.appendMsg("PDB", e.getMessage());
		}
	}

}
