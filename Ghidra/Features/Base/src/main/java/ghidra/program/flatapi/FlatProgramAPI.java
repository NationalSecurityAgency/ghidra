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
package ghidra.program.flatapi;

import java.io.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;

import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.function.DeleteFunctionCmd;
import ghidra.app.cmd.label.DeleteLabelCmd;
import ghidra.app.cmd.label.SetLabelPrimaryCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.clear.ClearCmd;
import ghidra.app.plugin.core.clear.ClearOptions;
import ghidra.app.plugin.core.searchmem.RegExSearchData;
import ghidra.app.script.GhidraScript;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.util.AddressEvaluator;
import ghidra.program.util.string.*;
import ghidra.util.Conv;
import ghidra.util.ascii.AsciiCharSetRecognizer;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.datastruct.ListAccumulator;
import ghidra.util.exception.*;
import ghidra.util.search.memory.*;
import ghidra.util.task.TaskMonitor;

/**
 * This class is a flattened version of the Program API.
 * <p>
 * NOTE:
 * <ol>
 * 	<li>NO METHODS SHOULD EVER BE REMOVED FROM THIS CLASS.
 * 	<li>NO METHOD SIGNATURES SHOULD EVER BE CHANGED IN THIS CLASS.
 * </ol>
 * <p>
 * This class is used by GhidraScript.
 * <p>
 * Changing this class will break user scripts.
 * <p>
 * That is bad. Don't do that.
 * <p>
 */
public class FlatProgramAPI {
	public static final int MAX_REFERENCES_TO = 0x1000;

	protected Program currentProgram;
	protected TaskMonitor monitor;

	private int transactionID = -1;

	/**
	 * Constructs a new flat program API.
	 * It will not be usable until the 'set' method has been called.
	 */
	protected FlatProgramAPI() {
		// empty
	}

	/**
	 * Constructs a new flat program API.
	 * @param program the program
	 */
	public FlatProgramAPI(Program program) {
		this(program, TaskMonitor.DUMMY);
	}

	/**
	 * Constructs a new flat program API.
	 * @param program the program
	 * @param monitor the task monitor
	 */
	public FlatProgramAPI(Program program, TaskMonitor monitor) {
		this.currentProgram = program;
		this.monitor = monitor;
		// ensure that auto-analysis manager has been activated for program
		AutoAnalysisManager.getAnalysisManager(program);
	}

	/**
	 * Sets the current state.
	 * @param program the program
	 * @param monitor the task monitor
	 */
	protected void set(Program program, TaskMonitor monitor) {
		this.currentProgram = program;
		this.monitor = monitor;
	}

	/**
	 * Gets the current program.
	 * @return the program
	 */
	public Program getCurrentProgram() {
		return currentProgram;
	}

	/**
	 * Gets the current task monitor.
	 * @return the task monitor
	 */
	public TaskMonitor getMonitor() {
		return monitor;
	}

	/**
	 * Starts a transaction on the current program.
	 */
	public final void start() {
		if (currentProgram == null) {
			return;
		}
		if (transactionID == -1) {
			transactionID = currentProgram.startTransaction(getClass().getName());
		}
	}

	/**
	 * Ends the transactions on the current program.
	 * @param commit true if changes should be committed
	 */
	public final void end(boolean commit) {
		if (currentProgram == null) {
			return;
		}
		if (transactionID != -1) {
			currentProgram.endTransaction(transactionID, commit);
			transactionID = -1;
		}
	}

	/**
	 * Returns the path to the program's executable file.
	 * For example, <code>c:\temp\test.exe</code>.
	 * @return path to program's executable file
	 */
	public final File getProgramFile() {
		File f = new File(currentProgram.getExecutablePath());
		if (f.exists()) {
			return f;
		}
		return null;
	}

	/**
	 * Start disassembling at the specified address.
	 * The disassembler will follow code flows.
	 * @param address the address to begin disassembling
	 * @return true if the program was successfully disassembled
	 */
	public final boolean disassemble(Address address) {
		DisassembleCommand cmd = new DisassembleCommand(address, null, true);
		return cmd.applyTo(currentProgram, monitor);
	}

	/**
	 * Starts auto-analysis on the specified program and performs complete analysis
	 * of the entire program.  This is usually only necessary if full analysis was never
	 * performed. This method will block until analysis completes.
	 * @param program the program to analyze
	 * @deprecated the method {@link #analyzeAll} or {@link #analyzeChanges} should be invoked.
	 * These separate methods were created to clarify their true behavior since many times it is
	 * only necessary to analyze changes and not the entire program which can take much
	 * longer and affect more of the program than is necessary.
	 */
	@Deprecated
	public void analyze(Program program) {
		analyzeAll(program);
	}

	/**
	 * Starts auto-analysis on the specified program and performs complete analysis
	 * of the entire program.  This is usually only necessary if full analysis was never
	 * performed. This method will block until analysis completes.
	 * @param program the program to analyze
	 */
	public void analyzeAll(Program program) {

		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);

		mgr.reAnalyzeAll(null);

		analyzeChanges(program);
	}

	/**
	 * Starts auto-analysis if not started and waits for pending analysis to complete.
	 * Only pending analysis on program changes is performed, including changes resulting
	 * from any analysis activity.  This method will block until analysis completes.
	 * NOTE: The auto-analysis manager will only detect program changes once it has been
	 * instantiated for a program (i.e, AutoAnalysisManager.getAnalysisManager(program) ).
	 * This is automatically done for the initial currentProgram, however, if a script is
	 * opening/instantiating its own programs it may be necessary to do this prior to
	 * making changes to the program.
	 * @param program the program to analyze
	 */
	public void analyzeChanges(Program program) {

		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);

		// analysis will start immediately in background if GUI analysis tool exists
		// and script is not running as analysis worker in background

		PluginTool analysisTool = mgr.getAnalysisTool();
		if (analysisTool == null || analysisTool.threadIsBackgroundTaskThread()) {
			mgr.startAnalysis(monitor, true); // yields to analysis
		}
		else {
			mgr.waitForAnalysis(null, monitor); // waits for all analaysis to complete
		}
	}

	/**
	 * Clears the code unit (instruction or data) defined at the address.
	 * @param address the address to clear the code unit
	 * @throws CancelledException
	 */
	public final void clearListing(Address address) throws CancelledException {
		clearListing(address, address);
	}

	/**
	 * Clears the code units (instructions or data) in the specified range.
	 * @param start the start address
	 * @param end   the end address
	 * @throws CancelledException
	 */
	public final void clearListing(Address start, Address end) throws CancelledException {
		currentProgram.getListing().clearCodeUnits(start, end, false, monitor);
	}

	/**
	 * Clears the code units (instructions or data) in the specified set
	 * @param set the set to clear
	 * @throws CancelledException
	 */
	public final void clearListing(AddressSetView set) throws CancelledException {
		AddressRangeIterator iter = set.getAddressRanges();
		while (iter.hasNext()) {
			if (monitor.isCancelled()) {
				break;
			}
			AddressRange range = iter.next();
			clearListing(range.getMinAddress(), range.getMaxAddress());
		}
	}

	/**
	 * Clears the listing in the specified address set.
	 * @param set  the address set where to clear
	 * @param code true if code units should be cleared (instructions and defined data)
	 * @param symbols true if symbols should be cleared
	 * @param comments true if comments should be cleared
	 * @param properties true if properties should be cleared
	 * @param functions true if functions should be cleared
	 * @param registers true if registers should be cleared
	 * @param equates true if equates should be cleared
	 * @param userReferences true if user references should be cleared
	 * @param analysisReferences true if analysis references should be cleared
	 * @param importReferences true if import references should be cleared
	 * @param defaultReferences true if default references should be cleared
	 * @param bookmarks true if bookmarks should be cleared
	 * @return true if the address set was successfully cleared
	 */
	public final boolean clearListing(AddressSetView set, boolean code, boolean symbols,
			boolean comments, boolean properties, boolean functions, boolean registers,
			boolean equates, boolean userReferences, boolean analysisReferences,
			boolean importReferences, boolean defaultReferences, boolean bookmarks) {

		ClearOptions options = new ClearOptions();
		options.setClearCode(code);
		options.setClearSymbols(symbols);
		options.setClearComments(comments);
		options.setClearProperties(properties);
		options.setClearFunctions(functions);
		options.setClearRegisters(registers);
		options.setClearEquates(equates);
		options.setClearUserReferences(userReferences);
		options.setClearAnalysisReferences(analysisReferences);
		options.setClearImportReferences(importReferences);
		options.setClearDefaultReferences(defaultReferences);
		options.setClearBookmarks(bookmarks);

		ClearCmd cmd = new ClearCmd(set, options);
		return cmd.applyTo(currentProgram, monitor);
	}

	/**
	 * Create a new memory block.
	 * If the input stream is null, then an uninitialized block will be created.
	 * @param name    the name of the block
	 * @param start   start address of the block
	 * @param input   source of the data used to fill the block.
	 * @param length  the size of the block
	 * @param overlay true will create an overlay, false will not
	 * @return the newly created memory block
	 */
	public final MemoryBlock createMemoryBlock(String name, Address start, InputStream input,
			long length, boolean overlay) throws Exception {
		if (input == null) {
			return currentProgram.getMemory()
					.createUninitializedBlock(name, start, length,
						overlay);
		}
		return currentProgram.getMemory()
				.createInitializedBlock(name, start, input, length,
					monitor, overlay);
	}

	/**
	 * Create a new memory block.
	 * @param name the name of the block
	 * @param start   start address of the block
	 * @param bytes   the bytes of the memory block
	 * @param overlay true will create an overlay, false will not
	 * @return the newly created memory block
	 */
	public final MemoryBlock createMemoryBlock(String name, Address start, byte[] bytes,
			boolean overlay) throws Exception {
		ByteArrayInputStream input = new ByteArrayInputStream(bytes);
		return currentProgram.getMemory()
				.createInitializedBlock(name, start, input, bytes.length,
					monitor, overlay);
	}

	/**
	 * Returns the first memory block with the specified name.
	 * NOTE: if more than block exists with the same name, the first
	 * block with that name will be returned.
	 * @param name the name of the requested block
	 * @return the the memory block with the specified name
	 */
	public final MemoryBlock getMemoryBlock(String name) {
		return currentProgram.getMemory().getBlock(name);
	}

	/**
	 * Returns the memory block containing the specified address,
	 * or null if no memory block contains the address.
	 * @param address the address
	 * @return the memory block containing the specified address
	 */
	public final MemoryBlock getMemoryBlock(Address address) {
		return currentProgram.getMemory().getBlock(address);
	}

	/**
	 * Returns an array containing all the memory blocks
	 * in the current program.
	 * @return an array containing all the memory blocks
	 */
	public final MemoryBlock[] getMemoryBlocks() {
		return currentProgram.getMemory().getBlocks();
	}

	/**
	 * Remove the memory block.
	 * NOTE: ALL ANNOTATION (disassembly, comments, etc) defined in this
	 * memory block will also be removed!
	 * @param block the block to be removed
	 */
	public final void removeMemoryBlock(MemoryBlock block) throws Exception {
		currentProgram.getMemory().removeBlock(block, monitor);
	}

	/**
	 * Creates a label at the specified address in the global namespace.
	 * If makePrimary==true, then the new label is made primary.
	 * @param address the address to create the symbol
	 * @param name the name of the symbol
	 * @param makePrimary true if the symbol should be made primary
	 * @return the newly created code or function symbol
	 */
	public final Symbol createLabel(Address address, String name, boolean makePrimary)
			throws Exception {
		return createLabel(address, name, makePrimary, SourceType.USER_DEFINED);
	}

	/**
	 * @deprecated use {@link #createLabel(Address, String, boolean)} instead.
	 * Deprecated in Ghidra 7.4
	 */
	@Deprecated
	public final Symbol createSymbol(Address address, String name, boolean makePrimary)
			throws Exception {
		return createLabel(address, name, makePrimary);
	}

	/**
	 * Creates a label at the specified address in the global namespace.
	 * If makePrimary==true, then the new label is made primary.
	 * If makeUnique==true, then if the name is a duplicate, the address
	 * will be concatenated to name to make it unique.
	 * @param address the address to create the symbol
	 * @param name the name of the symbol
	 * @param makePrimary true if the symbol should be made primary
	 * @param sourceType the source type.
	 * @return the newly created code or function symbol
	 */
	public final Symbol createLabel(Address address, String name, boolean makePrimary,
			SourceType sourceType) throws Exception {
		return createLabel(address, name, null, makePrimary, sourceType);
	}

	/**
	 * Creates a label at the specified address in the specified namespace.
	 * If makePrimary==true, then the new label is made primary if permitted.
	 * If makeUnique==true, then if the name is a duplicate, the address
	 * will be concatenated to name to make it unique.
	 * @param address the address to create the symbol
	 * @param name the name of the symbol
	 * @param namespace label's parent namespace
	 * @param makePrimary true if the symbol should be made primary
	 * @param sourceType the source type.
	 * @return the newly created code or function symbol
	 */
	public final Symbol createLabel(Address address, String name, Namespace namespace,
			boolean makePrimary, SourceType sourceType) throws Exception {
		Symbol symbol;
		SymbolTable symbolTable = currentProgram.getSymbolTable();
		symbol = symbolTable.createLabel(address, name, namespace, sourceType);
		if (makePrimary && !symbol.isPrimary()) {
			SetLabelPrimaryCmd cmd = new SetLabelPrimaryCmd(address, name, namespace);
			if (cmd.applyTo(currentProgram)) {
				symbol = cmd.getSymbol();
			}
		}
		return symbol;
	}

	/**
	 * @deprecated use {@link #createLabel(Address, String, boolean, SourceType)} instead. Deprecated in Ghidra 7.4
	 */
	@Deprecated
	public final Symbol createSymbol(Address address, String name, boolean makePrimary,
			boolean makeUnique, SourceType sourceType) throws Exception {
		return createLabel(address, name, makePrimary, sourceType);
	}

	/**
	 * Adds an entry point at the specified address.
	 * @param address address to create entry point
	 */
	public final void addEntryPoint(Address address) {
		currentProgram.getSymbolTable().addExternalEntryPoint(address);
	}

	/**
	 * Removes the entry point at the specified address.
	 * @param address address of entry point to remove
	 */
	public final void removeEntryPoint(Address address) {
		currentProgram.getSymbolTable().removeExternalEntryPoint(address);
	}

	/**
	 * Deletes the symbol with the specified name at the specified address.
	 * @param address the address of the symbol to delete
	 * @param name the name of the symbol to delete
	 * @return true if the symbol was deleted
	 */
	public final boolean removeSymbol(Address address, String name) {
		DeleteLabelCmd cmd = new DeleteLabelCmd(address, name);
		return cmd.applyTo(currentProgram);
	}

	/**
	 * Sets a PLATE comment at the specified address
	 * @param address the address to set the PLATE comment
	 * @param comment the PLATE comment
	 * @return true if the PLATE comment was successfully set
	 */
	public final boolean setPlateComment(Address address, String comment) {
		SetCommentCmd cmd = new SetCommentCmd(address, CodeUnit.PLATE_COMMENT, comment);
		return cmd.applyTo(currentProgram);
	}

	/**
	 * Sets a PRE comment at the specified address
	 * @param address the address to set the PRE comment
	 * @param comment the PRE comment
	 * @return true if the PRE comment was successfully set
	 */
	public final boolean setPreComment(Address address, String comment) {
		SetCommentCmd cmd = new SetCommentCmd(address, CodeUnit.PRE_COMMENT, comment);
		return cmd.applyTo(currentProgram);
	}

	/**
	 * Sets a POST comment at the specified address
	 * @param address the address to set the POST comment
	 * @param comment the POST comment
	 * @return true if the POST comment was successfully set
	 */
	public final boolean setPostComment(Address address, String comment) {
		SetCommentCmd cmd = new SetCommentCmd(address, CodeUnit.POST_COMMENT, comment);
		return cmd.applyTo(currentProgram);
	}

	/**
	 * Sets an EOL comment at the specified address
	 * @param address the address to set the EOL comment
	 * @param comment the EOL comment
	 * @return true if the EOL comment was successfully set
	 */
	public final boolean setEOLComment(Address address, String comment) {
		SetCommentCmd cmd = new SetCommentCmd(address, CodeUnit.EOL_COMMENT, comment);
		return cmd.applyTo(currentProgram);
	}

	/**
	 * Sets a repeatable comment at the specified address
	 * @param address the address to set the repeatable comment
	 * @param comment the repeatable comment
	 * @return true if the repeatable comment was successfully set
	 */
	public final boolean setRepeatableComment(Address address, String comment) {
		SetCommentCmd cmd = new SetCommentCmd(address, CodeUnit.REPEATABLE_COMMENT, comment);
		return cmd.applyTo(currentProgram);
	}

	/**
	 * Returns the PLATE comment at the specified address.  The comment returned is the raw text
	 * of the comment.  Contrastingly, calling {@link GhidraScript#getPlateCommentAsRendered(Address)} will
	 * return the text of the comment as it is rendered in the display.
	 *
	 * @param address the address to get the comment
	 * @return the PLATE comment at the specified address or null
	 * if one does not exist
	 * @see GhidraScript#getPlateCommentAsRendered(Address)
	 */
	public final String getPlateComment(Address address) {
		return currentProgram.getListing().getComment(CodeUnit.PLATE_COMMENT, address);
	}

	/**
	 * Returns the PRE comment at the specified address.  The comment returned is the raw text
	 * of the comment.  Contrastingly, calling {@link GhidraScript#getPreCommentAsRendered(Address)} will
	 * return the text of the comment as it is rendered in the display.
	 *
	 * @param address the address to get the comment
	 * @return the PRE comment at the specified address or null
	 * if one does not exist
	 * @see GhidraScript#getPreCommentAsRendered(Address)
	 */
	public final String getPreComment(Address address) {
		return currentProgram.getListing().getComment(CodeUnit.PRE_COMMENT, address);
	}

	/**
	 * Returns the POST comment at the specified address.  The comment returned is the raw text
	 * of the comment.  Contrastingly, calling {@link GhidraScript#getPostCommentAsRendered(Address)} will
	 * return the text of the comment as it is rendered in the display.
	 *
	 * @param address the address to get the comment
	 * @return the POST comment at the specified address or null
	 * if one does not exist
	 * @see GhidraScript#getPostCommentAsRendered(Address)
	 */
	public final String getPostComment(Address address) {
		return currentProgram.getListing().getComment(CodeUnit.POST_COMMENT, address);
	}

	/**
	 * Returns the EOL comment at the specified address.  The comment returned is the raw text
	 * of the comment.  Contrastingly, calling {@link GhidraScript#getEOLCommentAsRendered(Address)} will
	 * return the text of the comment as it is rendered in the display.
	 * @param address the address to get the comment
	 * @return the EOL comment at the specified address or null
	 * if one does not exist
	 * @see GhidraScript#getEOLCommentAsRendered(Address)
	 */
	public final String getEOLComment(Address address) {
		return currentProgram.getListing().getComment(CodeUnit.EOL_COMMENT, address);
	}

	/**
	 * Returns the repeatable comment at the specified address.  The comment returned is the raw text
	 * of the comment.  Contrastingly, calling {@link GhidraScript#getRepeatableCommentAsRendered(Address)} will
	 * return the text of the comment as it is rendered in the display.
	 * @param address the address to get the comment
	 * @return the repeatable comment at the specified address or null
	 * if one does not exist
	 * @see GhidraScript#getRepeatableCommentAsRendered(Address)
	 */
	public final String getRepeatableComment(Address address) {
		return currentProgram.getListing().getComment(CodeUnit.REPEATABLE_COMMENT, address);
	}

	/**
	 * Finds the first occurrence of the byte
	 * starting from the address. If the start address
	 * is null, then the find will start from the minimum address
	 * of the program.
	 * @param start the address to start searching
	 * @param value the byte to search for
	 * @return the first address where the byte was found
	 */
	public final Address find(Address start, byte value) {
		return find(start, new byte[] { value });
	}

	/**
	 * Finds the first occurrence of the byte array sequence
	 * starting from the address. If the start address
	 * is null, then the find will start from the minimum address
	 * of the program.
	 * @param start the address to start searching
	 * @param values the byte array sequence to search for
	 * @return the first address where the byte was found, or
	 * null if the bytes were not found
	 */
	public final Address find(Address start, byte[] values) {
		if (start == null) {
			start = currentProgram.getMinAddress();
		}
		return currentProgram.getMemory().findBytes(start, values, null, true, monitor);
	}

	/**
	 * Finds the first occurrence of the byte array sequence that matches the given byte string,
	 * starting from the address. If the start address is null, then the find will start
	 * from the minimum address of the program.
	 * <p>
	 * The <code>byteString</code> may contain regular expressions.  The following
	 * highlights some example search strings (note the use of double backslashes ("\\")):
	 * <pre>
	 *             "\\x80" - A basic search pattern for a byte value of 0x80
	 * "\\x50.{0,10}\\x55" - A regular expression string that searches for the byte 0x50
	 *                       followed by 0-10 occurrences of any byte value, followed
	 *                       by the byte 0x55
	 * </pre>
	 *
	 * @param start the address to start searching.  If null, then the start of the program
	 *        will be used.
	 * @param byteString the byte pattern for which to search
	 * @return the first address where the byte was found, or null if the bytes were not found
	 * @throws IllegalArgumentException if the byteString is not a valid regular expression
	 * @see #findBytes(Address, String, int)
	 */
	public final Address findBytes(Address start, String byteString) {
		Address[] matchingAddresses = findBytes(start, byteString, 1);
		if (matchingAddresses.length == 0) {
			return null;
		}
		return matchingAddresses[0];
	}

	/**
	 * Finds the first {@code <matchLimit>} occurrences of the byte array sequence that matches
	 * the given byte string, starting from the address. If the start address is null, then the
	 * find will start from the minimum address of the program.
	 * <p>
	 * The <code>byteString</code> may contain regular expressions.  The following
	 * highlights some example search strings (note the use of double backslashes ("\\")):
	 * <pre>
	 *             "\\x80" - A basic search pattern for a byte value of 0x80
	 * "\\x50.{0,10}\\x55" - A regular expression string that searches for the byte 0x50
	 *                       followed by 0-10 occurrences of any byte value, followed
	 *                       by the byte 0x55
	 * </pre>
	 *
	 * @param start the address to start searching.  If null, then the start of the program
	 *        will be used.
	 * @param byteString the byte pattern for which to search
	 * @param matchLimit The number of matches to which the search should be restricted
	 * @return the start addresses that contain byte patterns that match the given byteString
	 * @throws IllegalArgumentException if the byteString is not a valid regular expression
	 * @see #findBytes(Address, String)
	 */
	public final Address[] findBytes(Address start, String byteString, int matchLimit) {
		return findBytes(start, byteString, matchLimit, 1);
	}

	/**
	 * Finds the first {@code <matchLimit>} occurrences of the byte array sequence that matches
	 * the given byte string, starting from the address. If the start address is null, then the
	 * find will start from the minimum address of the program.
	 * <p>
	 * The <code>byteString</code> may contain regular expressions.  The following
	 * highlights some example search strings (note the use of double backslashes ("\\")):
	 * <pre>
	 *             "\\x80" - A basic search pattern for a byte value of 0x80
	 * "\\x50.{0,10}\\x55" - A regular expression string that searches for the byte 0x50
	 *                       followed by 0-10 occurrences of any byte value, followed
	 *                       by the byte 0x55
	 * </pre>
	 *
	 * @param start the address to start searching.  If null, then the start of the program
	 *        will be used.
	 * @param byteString the byte pattern for which to search
	 * @param matchLimit The number of matches to which the search should be restricted
	 * @param alignment byte alignment to use for search starts. For example, a value of
	 *    1 searches from every byte.  A value of 2 only matches runs that begin on a even
	 *    address boundary.
	 * @return the start addresses that contain byte patterns that match the given byteString
	 * @throws IllegalArgumentException if the byteString is not a valid regular expression
	 * @see #findBytes(Address, String)
	 */
	public final Address[] findBytes(Address start, String byteString, int matchLimit,
			int alignment) {

		if (start == null) {
			start = currentProgram.getMinAddress();
		}

		if (matchLimit <= 0) {
			matchLimit = 500;
		}

		Memory memory = currentProgram.getMemory();
		AddressFactory factory = currentProgram.getAddressFactory();
		AddressSet addressRange = factory.getAddressSet(start, memory.getMaxAddress());

		Address[] bytes = findBytes(addressRange, byteString, matchLimit, alignment, false);
		return bytes;
	}

	/**
	 * Finds a byte pattern within an addressSet.
	 *
	 * Note: The ranges within the addressSet are NOT treated as a contiguous set when searching
	 * <p>
	 * The <code>byteString</code> may contain regular expressions.  The following
	 * highlights some example search strings (note the use of double backslashes ("\\")):
	 * <pre>
	 *             "\\x80" - A basic search pattern for a byte value of 0x80
	 * "\\x50.{0,10}\\x55" - A regular expression string that searches for the byte 0x50
	 *                       followed by 0-10 occurrences of any byte value, followed
	 *                       by the byte 0x55
	 * </pre>
	 *
	 * @param set the addressSet specifying which addresses to search.
	 * @param byteString the byte pattern for which to search
	 * @param matchLimit The number of matches to which the search should be restricted
	 * @param alignment byte alignment to use for search starts. For example, a value of
	 *    1 searches from every byte.  A value of 2 only matches runs that begin on a even
	 *    address boundary.
	 * @return the start addresses that contain byte patterns that match the given byteString
	 * @throws IllegalArgumentException if the byteString is not a valid regular expression
	 * @see #findBytes(Address, String)
	 */
	public final Address[] findBytes(AddressSetView set, String byteString, int matchLimit,
			int alignment) {

		return findBytes(set, byteString, matchLimit, alignment, false);
	}

	/**
	 * Finds a byte pattern within an addressSet.
	 *
	 * Note: When searchAcrossAddressGaps is set to true, the ranges within the addressSet are
	 * treated as a contiguous set when searching.
	 *
	 * <p>
	 * The <code>byteString</code> may contain regular expressions.  The following
	 * highlights some example search strings (note the use of double backslashes ("\\")):
	 * <pre>
	 *             "\\x80" - A basic search pattern for a byte value of 0x80
	 * "\\x50.{0,10}\\x55" - A regular expression string that searches for the byte 0x50
	 *                       followed by 0-10 occurrences of any byte value, followed
	 *                       by the byte 0x55
	 * </pre>
	 *
	 * @param set the addressSet specifying which addresses to search.
	 * @param byteString the byte pattern for which to search
	 * @param matchLimit The number of matches to which the search should be restricted
	 * @param alignment byte alignment to use for search starts. For example, a value of
	 *        1 searches from every byte.  A value of 2 only matches runs that begin on a even
	 *        address boundary.
	 * @param searchAcrossAddressGaps when set to 'true' searches for matches across the gaps
	 *        of each addressRange contained in the addresSet.
	 * @return the start addresses that contain byte patterns that match the given byteString
	 * @throws IllegalArgumentException if the byteString is not a valid regular expression
	 * @see #findBytes(Address, String)
	 */
	public final Address[] findBytes(AddressSetView set, String byteString, int matchLimit,
			int alignment, boolean searchAcrossAddressGaps) {

		if (matchLimit <= 0) {
			matchLimit = 500;
		}

		RegExSearchData searchData = RegExSearchData.createRegExSearchData(byteString);

		//@formatter:off
		SearchInfo searchInfo = new SearchInfo(searchData,
											   matchLimit,
											   false,     // search selection
											   true,      // search forward
											   alignment,
											   true,      // include non-loaded blocks
											   null);
		//@formatter:on

		Memory memory = currentProgram.getMemory();
		AddressSet intersection = memory.getLoadedAndInitializedAddressSet().intersect(set);

		RegExMemSearcherAlgorithm searcher = new RegExMemSearcherAlgorithm(searchInfo, intersection,
			currentProgram, searchAcrossAddressGaps);

		Accumulator<MemSearchResult> accumulator = new ListAccumulator<>();
		searcher.search(accumulator, monitor);

		//@formatter:off
		List<Address> addresses =
			accumulator.stream()
                       .map(r -> r.getAddress())
                       .collect(Collectors.toList());
		//@formatter:on
		return addresses.toArray(new Address[addresses.size()]);
	}

	/**
	 * Finds the first occurrence of 'text' in the program listing.
	 * The search order is defined as:
	 * <ol>
	 * <li>PLATE comments</li>
	 * <li>PRE comments</li>
	 * <li>labels</li>
	 * <li>code unit mnemonics and operands</li>
	 * <li>EOL comments</li>
	 * <li>repeatable comments</li>
	 * <li>POST comments</li>
	 * </ol>
	 * @param text the text to search for
	 * @return the first address where the 'text' was found, or null
	 *  if the text was not found
	 */
	public final Address find(String text) {
		Address addr = null;

		monitor.setMessage("Searching plate comments...");
		addr = findComment(CodeUnit.PLATE_COMMENT, text);
		if (addr != null) {
			return addr;
		}

		monitor.setMessage("Searching pre comments...");
		addr = findComment(CodeUnit.PRE_COMMENT, text);
		if (addr != null) {
			return addr;
		}

		monitor.setMessage("Searching labels...");
		SymbolIterator symiter = currentProgram.getSymbolTable().getAllSymbols(true);
		while (symiter.hasNext() && !monitor.isCancelled()) {
			Symbol sym = symiter.next();
			if (currentProgram.getMemory().contains(sym.getAddress())) {
				if (sym.getName().indexOf(text) >= 0) {
					return sym.getAddress();
				}
			}
		}

		monitor.setMessage("Searching code units...");
		CodeUnitIterator cuIter = currentProgram.getListing().getCodeUnits(true);
		while (cuIter.hasNext() && !monitor.isCancelled()) {
			CodeUnit cu = cuIter.next();
			if (cu.getMnemonicString().indexOf(text) >= 0) {
				return cu.getMinAddress();
			}
			if (cu instanceof Instruction) {
				Instruction instr = (Instruction) cu;
				int nOps = instr.getNumOperands();
				for (int i = 0; i < nOps; ++i) {
					Object[] objs = instr.getOpObjects(i);
					for (Object element : objs) {
						String str = element.toString();
						if (str != null && str.indexOf(text) >= 0) {
							return instr.getMinAddress();
						}
					}
				}
			}
			if (cu instanceof Data) {
				Data data = (Data) cu;
				Object obj = data.getValue();
				if (obj != null) {
					String str = obj.toString();
					if (str != null && str.indexOf(text) >= 0) {
						return data.getMinAddress();
					}
				}
			}
		}

		monitor.setMessage("Searching eol comments...");
		addr = findComment(CodeUnit.EOL_COMMENT, text);
		if (addr != null) {
			return addr;
		}

		monitor.setMessage("Searching repeatable comments...");
		addr = findComment(CodeUnit.REPEATABLE_COMMENT, text);
		if (addr != null) {
			return addr;
		}

		monitor.setMessage("Searching post comments...");
		addr = findComment(CodeUnit.POST_COMMENT, text);
		if (addr != null) {
			return addr;
		}

		return null;
	}

	/**
	 * Search for sequences of Ascii strings in program memory.  See {@link AsciiCharSetRecognizer}
	 * to see exactly what chars are considered ASCII for purposes of this search.
	 * @param addressSet The address set to search. Use null to search all memory;
	 * @param minimumStringLength The smallest number of chars in a sequence to be considered a "string".
	 * @param alignment specifies any alignment requirements for the start of the string.  An alignment
	 * of 1, means the string can start at any address.  An alignment of 2 means the string must
	 * start on an even address and so on.  Only allowed values are 1,2, and 4.
	 * @param requireNullTermination If true, only strings that end in a null will be returned.
	 * @param includeAllCharWidths if true, UTF16 and UTF32 size strings will be included in addition to UTF8.
	 * @return a list of "FoundString" objects which contain the addresses, length, and type of possible strings.
	 */
	public List<FoundString> findStrings(AddressSetView addressSet, int minimumStringLength,
			int alignment, boolean requireNullTermination, boolean includeAllCharWidths) {

		final List<FoundString> list = new ArrayList<>();
		FoundStringCallback foundStringCallback = foundString -> list.add(foundString);

		StringSearcher searcher = new StringSearcher(currentProgram, minimumStringLength, alignment,
			includeAllCharWidths, requireNullTermination);

		searcher.search(addressSet, foundStringCallback, true, monitor);

		return list;
	}

	/**
	 * Search for sequences of Pascal Ascii strings in program memory.  See {@link AsciiCharSetRecognizer}
	 * to see exactly what chars are considered ASCII for purposes of this search.
	 * @param addressSet The address set to search. Use null to search all memory;
	 * @param minimumStringLength The smallest number of chars in a sequence to be considered a "string".
	 * @param alignment specifies any alignment requirements for the start of the string.  An alignment
	 * of 1, means the string can start at any address.  An alignment of 2 means the string must
	 * start on an even address and so on.  Only allowed values are 1,2, and 4.
	 * @param includePascalUnicode if true, UTF16 size strings will be included in addition to UTF8.
	 * @return a list of "FoundString" objects which contain the addresses, length, and type of possible strings.
	 */
	public List<FoundString> findPascalStrings(AddressSetView addressSet, int minimumStringLength,
			int alignment, boolean includePascalUnicode) {
		final List<FoundString> list = new ArrayList<>();
		FoundStringCallback foundStringCallback = foundString -> list.add(foundString);

		PascalStringSearcher searcher = new PascalStringSearcher(currentProgram,
			minimumStringLength, alignment, includePascalUnicode);

		searcher.search(addressSet, foundStringCallback, true, monitor);

		return list;
	}

	/**
	 * Creates a function at entry point with the specified name
	 * @param entryPoint the entry point of the function
	 * @param name the name of the function or null for a default function
	 * @return the new function or null if the function was not created
	 */
	public final Function createFunction(Address entryPoint, String name) {
		CreateFunctionCmd cmd = new CreateFunctionCmd(name, entryPoint, null,
			name != null ? SourceType.USER_DEFINED : SourceType.DEFAULT);
		if (cmd.applyTo(currentProgram, monitor)) {
			return currentProgram.getListing().getFunctionAt(entryPoint);
		}
		return null;
	}

	/**
	 * Removes the function from the current program.
	 * @param function the function to remove
	 */
	public final void removeFunction(Function function) {
		removeFunctionAt(function.getEntryPoint());
	}

	/**
	 * Removes the function with the given entry point.
	 * @param entryPoint the entry point of the function to remove
	 */
	public final void removeFunctionAt(Address entryPoint) {
		DeleteFunctionCmd cmd = new DeleteFunctionCmd(entryPoint);
		cmd.applyTo(currentProgram);
	}

	/**
	 * Returns the function with the specified entry point, or
	 * null if no function exists.
	 * @param entryPoint the function entry point address
	 * @return the function with the specified entry point, or
	 * null if no function exists
	 */
	public final Function getFunctionAt(Address entryPoint) {
		return currentProgram.getListing().getFunctionAt(entryPoint);
	}

	/**
	 * Returns the function containing the specified address.
	 * @param address the address
	 * @return the function containing the specified address
	 */
	public final Function getFunctionContaining(Address address) {
		return currentProgram.getListing().getFunctionContaining(address);
	}

	/**
	 * Returns the function defined before the specified function in address order.
	 * @param function the function
	 * @return the function defined before the specified function
	 */
	public final Function getFunctionBefore(Function function) {
		if (function == null) {
			return null;
		}
		Address start = function.getEntryPoint();
		return getFunctionBefore(start);
	}

	/**
	 * Returns the function defined before the specified address.
	 * @param address the address
	 * @return the function defined before the specified address
	 */
	public final Function getFunctionBefore(Address address) {
		FunctionIterator iterator = currentProgram.getListing().getFunctions(address, false);
		// skip over this function.
		// This is weird, but if you have multiple overlay spaces or address spaces,
		// you WILL miss functions by not using the iterator and doing address math yourself.
		if (!iterator.hasNext()) {
			return null;
		}
		Function func = iterator.next();
		// if the function found starts at the start addres, go to the next one.
		if (address.equals(func.getEntryPoint())) {
			func = null;
			if (iterator.hasNext()) {
				func = iterator.next();
			}
		}

		return func;
	}

	/**
	 * Returns the function defined before the specified function in address order.
	 * @param function the function
	 * @return the function defined before the specified function
	 */
	public final Function getFunctionAfter(Function function) {
		if (function == null) {
			return null;
		}

		Address start = function.getEntryPoint();

		return getFunctionAfter(start);
	}

	/**
	 * Returns the function defined after the specified address.
	 * @param address the address
	 * @return the function defined after the specified address
	 */
	public final Function getFunctionAfter(Address address) {
		FunctionIterator iterator = currentProgram.getListing().getFunctions(address, true);
		// skip over this function.
		// This is weird, but if you have multiple overlay spaces or address spaces,
		// you WILL miss functions by not using the iterator and doing address math yourself.
		if (!iterator.hasNext()) {
			return null;
		}
		Function func = iterator.next();
		// if the function found starts at the start addres, go to the next one.
		if (address.equals(func.getEntryPoint())) {
			func = null;
			if (iterator.hasNext()) {
				func = iterator.next();
			}
		}

		return func;
	}

	/**
	 * Returns the function with the specified name, or
	 * null if no function exists. (Now returns the first one it finds with that name)
	 * @param name the name of the function
	 * @return the function with the specified name, or
	 * null if no function exists
	 * @deprecated this method makes no sense in the new world order where function  names
	 * 			   no longer have to be unique. Use {@link #getGlobalFunctions(String)}
	 * 			   Deprecated in Ghidra 7.4
	 */
	@Deprecated
	public final Function getFunction(String name) {
		List<Function> globalFunctions = currentProgram.getListing().getGlobalFunctions(name);
		return globalFunctions.isEmpty() ? null : globalFunctions.get(0);
	}

	/**
	 * Returns a list of all functions in the global namespace with the given name.
	 * @param name the name of the function
	 * @return the function with the specified name, or
	 */
	public final List<Function> getGlobalFunctions(String name) {
		return currentProgram.getListing().getGlobalFunctions(name);
	}

	/**
	 * Returns the first function in the current program.
	 * @return the first function in the current program
	 */
	public final Function getFirstFunction() {
		FunctionIterator iterator = currentProgram.getListing().getFunctions(true);
		if (iterator.hasNext()) {
			return iterator.next();
		}
		return null;
	}

	/**
	 * Returns the last function in the current program.
	 * @return the last function in the current program
	 */
	public final Function getLastFunction() {
		FunctionIterator iterator = currentProgram.getListing().getFunctions(false);
		if (iterator.hasNext()) {
			return iterator.next();
		}
		return null;
	}

	/**
	 * Returns the first instruction in the current program.
	 * @return the first instruction in the current program
	 */
	public final Instruction getFirstInstruction() {
		Address address = currentProgram.getMinAddress();
		InstructionIterator iterator = currentProgram.getListing().getInstructions(address, true);
		if (iterator.hasNext()) {
			return iterator.next();
		}
		return null;
	}

	/**
	 * Returns the first instruction in the function.
	 * @return the first instruction in the function
	 */
	public final Instruction getFirstInstruction(Function function) {
		Address address = function.getEntryPoint();
		return getInstructionAt(address);
	}

	/**
	 * Returns the last instruction in the current program.
	 * @return the last instruction in the current program
	 */
	public final Instruction getLastInstruction() {
		Address address = currentProgram.getMinAddress();
		InstructionIterator iterator = currentProgram.getListing().getInstructions(address, false);
		if (iterator.hasNext()) {
			return iterator.next();
		}
		return null;
	}

	/**
	 * Returns the instruction at the specified address or null if no instruction exists.
	 * @param address the instruction address
	 * @return the instruction at the specified address or null if no instruction exists
	 */
	public final Instruction getInstructionAt(Address address) {
		return currentProgram.getListing().getInstructionAt(address);
	}

	/**
	 * Returns the instruction containing the specified address or null if no instruction exists.
	 * @param address the instruction address
	 * @return the instruction containing the specified address or null if no instruction exists
	 */
	public final Instruction getInstructionContaining(Address address) {
		return currentProgram.getListing().getInstructionContaining(address);
	}

	/**
	 * Returns the instruction defined before the specified instruction or null
	 * if no instruction exists.
	 * The instruction that is returned does not have to be contiguous.
	 * @param instruction the instruction
	 * @return the instruction defined before the specified instruction or null if no instruction exists
	 */
	public final Instruction getInstructionBefore(Instruction instruction) {
		return getInstructionBefore(instruction.getMinAddress());
	}

	/**
	 * Returns the instruction defined before the specified address or null
	 * if no instruction exists.
	 * The instruction that is returned does not have to be contiguous.
	 * @param address the address of the instruction
	 * @return the instruction defined before the specified address or null if no instruction exists
	 */
	public final Instruction getInstructionBefore(Address address) {
		return currentProgram.getListing().getInstructionBefore(address);
	}

	/**
	 * Returns the instruction defined after the specified instruction or null
	 * if no instruction exists.
	 * The instruction that is returned does not have to be contiguous.
	 * @param instruction the instruction
	 * @return the instruction defined after the specified instruction or null if no instruction exists
	 */
	public final Instruction getInstructionAfter(Instruction instruction) {
		return getInstructionAfter(instruction.getMaxAddress());
	}

	/**
	 * Returns the instruction defined after the specified address or null
	 * if no instruction exists.
	 * The instruction that is returned does not have to be contiguous.
	 * @param address the address of the prior instruction
	 * @return the instruction defined after the specified address or null if no instruction exists
	 */
	public final Instruction getInstructionAfter(Address address) {
		return currentProgram.getListing().getInstructionAfter(address);
	}

	/**
	 * Returns the first defined data in the current program.
	 * @return the first defined data in the current program
	 */
	public final Data getFirstData() {
		Address address = currentProgram.getMinAddress();
		DataIterator iterator = currentProgram.getListing().getData(address, true);
		if (iterator.hasNext()) {
			return iterator.next();
		}
		return null;
	}

	/**
	 * Returns the last defined data in the current program.
	 * @return the last defined data in the current program
	 */
	public final Data getLastData() {
		Address address = currentProgram.getMaxAddress();
		DataIterator iterator = currentProgram.getListing().getData(address, false);
		if (iterator.hasNext()) {
			return iterator.next();
		}
		return null;
	}

	/**
	 * Returns the defined data at the specified address or null if no data exists.
	 * @param address the data address
	 * @return the data at the specified address or null if no data exists
	 */
	public final Data getDataAt(Address address) {
		return currentProgram.getListing().getDefinedDataAt(address);
	}

	/**
	 * Returns the defined data containing the specified address or null if no data exists.
	 * @param address the data address
	 * @return the defined data containing the specified address or null if no data exists
	 */
	public final Data getDataContaining(Address address) {
		return currentProgram.getListing().getDefinedDataContaining(address);
	}

	/**
	 * Returns the defined data before the specified data or null if no data exists.
	 * @param data the succeeding data
	 * @return the defined data before the specified data or null if no data exists
	 */
	public final Data getDataBefore(Data data) {
		return getDataBefore(data.getMinAddress());
	}

	/**
	 * Returns the defined data before the specified address or null if no data exists.
	 * @param address the data address
	 * @return the defined data before the specified address or null if no data exists
	 */
	public final Data getDataBefore(Address address) {
		return currentProgram.getListing().getDefinedDataBefore(address);
	}

	/**
	 * Returns the defined data after the specified data or null if no data exists.
	 * @param data preceeding data
	 * @return the defined data after the specified data or null if no data exists
	 */
	public final Data getDataAfter(Data data) {
		return getDataAfter(data.getMaxAddress());
	}

	/**
	 * Returns the defined data after the specified address or null if no data exists.
	 * @param address the data address
	 * @return the defined data after the specified address or null if no data exists
	 */
	public final Data getDataAfter(Address address) {
		return currentProgram.getListing().getDefinedDataAfter(address);
	}

	/**
	 * Returns the undefined data at the specified address or null if no undefined data exists.
	 * @param address the undefined data address
	 * @return the undefined data at the specified address or null if no undefined data exists
	 */
	public final Data getUndefinedDataAt(Address address) {
		return currentProgram.getListing().getUndefinedDataAt(address);
	}

	/**
	 * Returns the undefined data before the specified address or null if no undefined data exists.
	 * @param address the undefined data address
	 * @return the undefined data before the specified address or null if no undefined data exists
	 */
	public final Data getUndefinedDataBefore(Address address) {
		return currentProgram.getListing().getUndefinedDataBefore(address, monitor);
	}

	/**
	 * Returns the undefined data after the specified address or null if no undefined data exists.
	 * @param address the undefined data address
	 * @return the undefined data after the specified address or null if no undefined data exists
	 */
	public final Data getUndefinedDataAfter(Address address) {
		return currentProgram.getListing().getUndefinedDataAfter(address, monitor);
	}

	/**
	 * Returns the symbol with the specified address and name, or
	 * null if no symbol exists.
	 * @param address the symbol address
	 * @param name the symbol name
	 * @return the symbol with the specified address and name, or
	 * null if no symbol exists
	 * @deprecated Since the same label name can be at the same address if in a different namespace,
	 * this method is ambiguous. Use {@link #getSymbolAt(Address, String, Namespace)} instead.
	 */
	@Deprecated
	public final Symbol getSymbolAt(Address address, String name) {
		Symbol[] symbols = currentProgram.getSymbolTable().getSymbols(address);
		for (Symbol symbol : symbols) {
			if (symbol.getName().equals(name)) {
				return symbol;
			}
		}
		return null;
	}

	/**
	 * Returns the symbol with the specified address, name, and namespace
	 *
	 * @param address the symbol address
	 * @param name the symbol name
	 * @param namespace the parent namespace for the symbol.
	 * @return the symbol with the specified address, name, and namespace, or
	 * null if no symbol exists
	 */
	public final Symbol getSymbolAt(Address address, String name, Namespace namespace) {
		return currentProgram.getSymbolTable().getSymbol(name, address, namespace);
	}

	/**
	 * Returns the next non-default primary symbol defined
	 * after the given symbol.
	 * @param symbol the symbol to use as a starting point
	 * @return the next non-default primary symbol
	 */
	public final Symbol getSymbolAfter(Symbol symbol) {
		return getSymbolAfter(symbol.getAddress());
	}

	/**
	 * Returns the next non-default primary symbol defined
	 * after the given address.
	 * @param address the address to use as a starting point
	 * @return the next non-default primary symbol
	 */
	public final Symbol getSymbolAfter(Address address) {
		SymbolIterator iterator =
			currentProgram.getSymbolTable().getPrimarySymbolIterator(address.add(1), true);
		if (iterator.hasNext()) {
			return iterator.next();
		}
		return null;
	}

	/**
	 * Returns the previous non-default primary symbol defined
	 * before the given symbol.
	 * @param symbol the symbol to use as a starting point
	 * @return the previous non-default primary symbol
	 */
	public final Symbol getSymbolBefore(Symbol symbol) {
		return getSymbolBefore(symbol.getAddress());
	}

	/**
	 * Returns the previous non-default primary symbol defined
	 * after the previous address.
	 * @param address the address to use as a starting point
	 * @return the next non-default primary symbol
	 */
	public final Symbol getSymbolBefore(Address address) {
		SymbolIterator iterator =
			currentProgram.getSymbolTable().getSymbolIterator(address.subtract(1), false);
		if (iterator.hasNext()) {
			return iterator.next();
		}
		return null;
	}

	/**
	 * Returns the PRIMARY symbol at the specified address, or
	 * null if no symbol exists.
	 * @param address the symbol address
	 * @return the PRIMARY symbol at the specified address, or
	 * null if no symbol exists
	 */
	public final Symbol getSymbolAt(Address address) {
		return currentProgram.getSymbolTable().getPrimarySymbol(address);
	}

	/**
	 * Returns the symbol with the given name in the given namespace if there is only one.
	 * Pass <code>null</code> for namespace to indicate the global namespace.
	 * @param name the name of the symbol
	 * @param namespace the parent namespace, or null for global namespace
	 * @return the symbol with the given name in the given namespace
	 * @throws IllegalStateException if there is more than one symbol with that name.
	 * @deprecated use {@link #getSymbols(String, Namespace)}
	 */
	@Deprecated
	public final Symbol getSymbol(String name, Namespace namespace) {
		List<Symbol> symbols = currentProgram.getSymbolTable().getSymbols(name, namespace);
		if (symbols.size() == 1) {
			return symbols.get(0);
		}
		else if (symbols.size() > 1) {
			throw new IllegalStateException(
				"There are multiple symbols named " + name + " in namespace " + namespace);
		}
		return null;
	}

	/**
	 * Returns a list of all the symbols with the given name in the given namespace.
	 * @param name the name of the symbols to retrieve.
	 * @param namespace the namespace containing the symbols, or null for the global namespace.
	 * @return a list of all the symbols with the given name in the given namespace.
	 */
	public final List<Symbol> getSymbols(String name, Namespace namespace) {
		return currentProgram.getSymbolTable().getSymbols(name, namespace);
	}

	/**
	 * Returns the non-function namespace with the given name contained inside the
	 * specified parent namespace.
	 * Pass <code>null</code> for namespace to indicate the global namespace.
	 * @param parent the parent namespace, or null for global namespace
	 * @param namespaceName the requested namespace's name
	 * @return the namespace with the given name or null if not found
	 */
	public final Namespace getNamespace(Namespace parent, String namespaceName) {
		return currentProgram.getSymbolTable().getNamespace(namespaceName, parent);
	}

	/**
	 * Creates a fragment in the root folder of the default program tree.
	 * @param fragmentName the name of the fragment
	 * @param start the start address
	 * @param end the end address (NOT INCLUSIVE)
	 * @return the newly created fragment
	 * @throws DuplicateNameException if the given fragment name already exists
	 * @throws NotFoundException if any address in the fragment would be outside of the program
	 * @deprecated This method is deprecated because it did not allow you to include the
	 * largest possible address.  Instead use the one that takes a start address and a length.
	 */
	@Deprecated
	public final ProgramFragment createFragment(String fragmentName, Address start, Address end)
			throws DuplicateNameException, NotFoundException {
		ProgramModule module = currentProgram.getListing().getDefaultRootModule();
		return createFragment(module, fragmentName, start, end);
	}

	/**
	 * Creates a fragment in the root folder of the default program tree.
	 * @param fragmentName the name of the fragment
	 * @param start the start address
	 * @param length the length of the fragment
	 * @return the newly created fragment
	 * @throws DuplicateNameException if the given fragment name already exists
	 * @throws NotFoundException if any address in the fragment would be outside of the program
	 */
	public final ProgramFragment createFragment(String fragmentName, Address start, long length)
			throws DuplicateNameException, NotFoundException {
		ProgramModule module = currentProgram.getListing().getDefaultRootModule();
		return createFragment(module, fragmentName, start, length);
	}

	/**
	 * Creates a fragment in the given folder of the default program tree.
	 * @param module the parent module (or folder)
	 * @param fragmentName the name of the fragment
	 * @param start the start address
	 * @param end the end address (NOT INCLUSIVE)
	 * @return the newly created fragment
	 * @throws DuplicateNameException if the given fragment name already exists
	 * @throws NotFoundException if any address in the fragment would be outside of the program
	 * @deprecated This method is deprecated because it did not allow you to include the
	 * largest possible address.  Instead use the one that takes a start address and a length.
	 */
	@Deprecated
	public final ProgramFragment createFragment(ProgramModule module, String fragmentName,
			Address start, Address end) throws DuplicateNameException, NotFoundException {
		ProgramFragment fragment = getFragment(module, fragmentName);
		if (fragment == null) {
			fragment = module.createFragment(fragmentName);
		}
		fragment.move(start, end.subtract(1));
		return fragment;
	}

	/**
	 * Creates a fragment in the given folder of the default program tree.
	 * @param module the parent module (or folder)
	 * @param fragmentName the name of the fragment
	 * @param start the start address
	 * @param length the length of the fragment
	 * @return the newly created fragment
	 * @throws DuplicateNameException if the given fragment name already exists
	 * @throws NotFoundException if any address in the fragment would be outside of the program
	 */
	public final ProgramFragment createFragment(ProgramModule module, String fragmentName,
			Address start, long length) throws DuplicateNameException, NotFoundException {
		ProgramFragment fragment = getFragment(module, fragmentName);
		if (fragment == null) {
			fragment = module.createFragment(fragmentName);
		}
		fragment.move(start, start.add(length - 1));
		return fragment;
	}

	/**
	 * Returns the fragment with the specified name
	 * defined in the given module.
	 * @param module the parent module
	 * @param fragmentName the fragment name
	 * @return the fragment or null if one does not exist
	 */
	public final ProgramFragment getFragment(ProgramModule module, String fragmentName) {
		Group[] groups = module.getChildren();
		for (Group group : groups) {
			if (group.getName().equals(fragmentName)) {
				return (ProgramFragment) group;
			}
		}
		return null;
	}

	/**
	 * Creates a new mutable address set.
	 * @return a new mutable address set
	 */
	public final AddressSet createAddressSet() {
		return new AddressSet();
	}

	public final AddressFactory getAddressFactory() {
		if (currentProgram != null) {
			return currentProgram.getAddressFactory();
		}
		return null;
	}

	/**
	 * Searches through the datatype manager of the current program and
	 * returns an array of datatypes that match the specified name.
	 * The datatype manager supports datatypes of the same name in different categories.
	 * A zero-length array indicates that no datatypes with the specified name exist.
	 * @param name the name of the desired datatype
	 * @return an array of datatypes that match the specified name
	 */
	public final DataType[] getDataTypes(String name) {
		ArrayList<DataType> list = new ArrayList<>();
		currentProgram.getDataTypeManager().findDataTypes(name, list);
		DataType[] dtarr = new DataType[list.size()];
		list.toArray(dtarr);
		return dtarr;
	}

	/**
	 * Creates a new defined Data object at the given address.
	 * @param address the address at which to create a new Data object.
	 * @param datatype the Data Type that describes the type of Data object to create.
	 * @return the newly created Data object
	 */
	public final Data createData(Address address, DataType datatype) throws Exception {
		Listing listing = currentProgram.getListing();
		Data d = listing.getDefinedDataAt(address);
		if (d != null) {
			if (d.getDataType().isEquivalent(datatype)) {
				return d;
			}
			throw new CodeUnitInsertionException("Data conflict at address " + address);
		}
		return listing.createData(address, datatype);
	}

	/**
	 * Creates a byte datatype at the given address.
	 * @param address the address to create the byte
	 * @return the newly created Data object
	 */
	public final Data createByte(Address address) throws Exception {
		return createData(address, new ByteDataType());
	}

	/**
	 * Creates a word datatype at the given address.
	 * @param address the address to create the word
	 * @return the newly created Data object
	 */
	public final Data createWord(Address address) throws Exception {
		return createData(address, new WordDataType());
	}

	/**
	 * Creates a dword datatype at the given address.
	 * @param address the address to create the dword
	 * @return the newly created Data object
	 */
	public final Data createDWord(Address address) throws Exception {
		return createData(address, new DWordDataType());
	}

	/**
	 * Creates a list of dword datatypes starting at the given address.
	 * @param start the start address to create the dwords
	 * @param count the number of dwords to create
	 */
	public final void createDwords(Address start, int count) throws Exception {
		for (int i = 0; i < count; ++i) {
			Address address = start.add(i * DWordDataType.dataType.getLength());
			createDWord(address);
		}
	}

	/**
	 * Creates a qword datatype at the given address.
	 * @param address the address to create the qword
	 * @return the newly created Data object
	 */
	public final Data createQWord(Address address) throws Exception {
		return createData(address, new QWordDataType());
	}

	/**
	 * Creates a float datatype at the given address.
	 * @param address the address to create the float
	 * @return the newly created Data object
	 */
	public final Data createFloat(Address address) throws Exception {
		return createData(address, new FloatDataType());
	}

	/**
	 * Creates a double datatype at the given address.
	 * @param address the address to create the double
	 * @return the newly created Data object
	 */
	public final Data createDouble(Address address) throws Exception {
		return createData(address, new DoubleDataType());
	}

	/**
	 * Creates a char datatype at the given address.
	 * @param address the address to create the char
	 * @return the newly created Data object
	 */
	public final Data createChar(Address address) throws Exception {
		return createData(address, new CharDataType());
	}

	/**
	 * Creates a null terminated ascii string starting
	 * at the specified address.
	 * @param address the address to create the string
	 * @return the newly created Data object
	 */
	public final Data createAsciiString(Address address) throws Exception {
		return createData(address, new TerminatedStringDataType());
	}

	/**
	 * Create an ASCII string at the specified address.
	 * @param address
	 * @param length length of string (a value of 0 or negative will force use
	 * of dynamic null terminated string)
	 * @return string data created
	 * @throws CodeUnitInsertionException
	 * @throws DataTypeConflictException
	 */
	public final Data createAsciiString(Address address, int length)
			throws CodeUnitInsertionException {
		Listing listing = currentProgram.getListing();
		DataType dt = StringDataType.dataType;
		if (length <= 0) {
			dt = TerminatedStringDataType.dataType;
			length = -1;
		}
		Data d = listing.getDefinedDataAt(address);
		if (d != null) {
			if (d.getDataType().isEquivalent(dt) || (length > 0 && length != d.getLength())) {
				throw new CodeUnitInsertionException("Data conflict at address " + address);
			}
		}
		else {
			d = listing.createData(address, dt, length);
		}
		return d;
	}

	/**
	 * Creates a null terminated unicode string starting
	 * at the specified address.
	 * @param address the address to create the string
	 * @return the newly created Data object
	 * @throws Exception
	 */
	public final Data createUnicodeString(Address address) throws Exception {
		return createData(address, new TerminatedUnicodeDataType());
	}

	/**
	 * Removes the given data from the current program.
	 * @param data the data to remove
	 */
	public final void removeData(Data data) throws Exception {
		clearListing(data.getMinAddress(), data.getMaxAddress());
	}

	/**
	 * Removes the data containing the given address from the current program.
	 * @param address the address to remove data
	 */
	public final void removeDataAt(Address address) throws Exception {
		Data data = getDataContaining(address);
		if (data != null) {
			removeData(data);
		}
	}

	/**
	 * Removes the given instruction from the current program.
	 * @param instruction the instruction to remove
	 */
	public final void removeInstruction(Instruction instruction) throws Exception {
		clearListing(instruction.getMinAddress(), instruction.getMaxAddress());
	}

	/**
	 * Removes the instruction containing the given address from the current program.
	 * @param address the address to remove instruction
	 */
	public final void removeInstructionAt(Address address) throws Exception {
		Instruction instruction = getInstructionContaining(address);
		if (instruction != null) {
			removeInstruction(instruction);
		}
	}

	/**
	 * Adds a cross reference (XREF).
	 * @param from     the source address of the reference
	 * @param to       the destination address of the reference
	 * @param opIndex  the operand index (-1 indicates the mnemonic)
	 * @param type     the flow type
	 * @return the newly created reference
	 * @see ghidra.program.model.symbol.FlowType
	 * @see ghidra.program.model.symbol.Reference
	 */
	public final Reference addInstructionXref(Address from, Address to, int opIndex,
			FlowType type) {
		return currentProgram.getReferenceManager()
				.addMemoryReference(from, to, type,
					SourceType.USER_DEFINED, opIndex);
	}

	/**
	 * Returns a new address with the specified offset in the default address space.
	 * @param offset the offset for the new address
	 * @return a new address with the specified offset in the default address space
	 */
	public final Address toAddr(int offset) {
		return toAddr(offset & Conv.INT_MASK);
	}

	/**
	 * Returns a new address with the specified offset in the default address space.
	 * @param offset the offset for the new address
	 * @return a new address with the specified offset in the default address space
	 */
	public final Address toAddr(long offset) {
		return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	/**
	 * Returns a new address inside the specified program as indicated by the string.
	 * @param addressString string representation of the address desired
	 * @return the address. Otherwise, return null if the string fails to evaluate
	 * to a legitimate address
	 */
	public final Address toAddr(String addressString) {
		return AddressEvaluator.evaluate(currentProgram, addressString);
	}

	/**
	 * Returns the 'byte' value at the specified address in memory.
	 * @param address the address
	 * @return the 'byte' value at the specified address in memory
	 * @throws MemoryAccessException if the memory is not readable
	 */
	public final byte getByte(Address address) throws MemoryAccessException {
		return currentProgram.getMemory().getByte(address);
	}

	/**
	 * Reads length number of bytes starting at the specified address.
	 * Note: this could be inefficient if length is large
	 * @param address the address to start reading
	 * @param length the number of bytes to read
	 * @return an array of bytes
	 * @throws MemoryAccessException if memory does not exist or is uninitialized
	 * @see ghidra.program.model.mem.Memory
	 */
	public final byte[] getBytes(Address address, int length) throws MemoryAccessException {
		byte[] bytes = new byte[length];
		currentProgram.getMemory().getBytes(address, bytes);
		return bytes;
	}

	/**
	 * Sets the 'byte' value at the specified address.
	 * @param address the address to set the 'byte'
	 * @param value the value to set
	 * @throws MemoryAccessException if memory does not exist or is uninitialized
	 */
	public final void setByte(Address address, byte value) throws MemoryAccessException {
		currentProgram.getMemory().setByte(address, value);
	}

	/**
	 * Sets the 'byte' values starting at the specified address.
	 * @param address the address to set the bytes
	 * @param values the values to set
	 * @throws MemoryAccessException if memory does not exist or is uninitialized
	 */
	public final void setBytes(Address address, byte[] values) throws MemoryAccessException {
		currentProgram.getMemory().setBytes(address, values);
	}

	/**
	 * Returns the 'short' value at the specified address in memory.
	 * @param address the address
	 * @return the 'short' value at the specified address in memory
	 * @throws MemoryAccessException if the memory is not readable
	 */
	public final short getShort(Address address) throws MemoryAccessException {
		return currentProgram.getMemory().getShort(address);
	}

	/**
	 * Sets the 'short' value at the specified address.
	 * @param address the address to set the 'short'
	 * @param value the value to set
	 * @throws MemoryAccessException if memory does not exist or is uninitialized
	 */
	public final void setShort(Address address, short value) throws MemoryAccessException {
		currentProgram.getMemory().setShort(address, value);
	}

	/**
	 * Returns the 'integer' value at the specified address in memory.
	 * @param address the address
	 * @return the 'integer' value at the specified address in memory
	 * @throws MemoryAccessException if the memory is not readable
	 */
	public final int getInt(Address address) throws MemoryAccessException {
		return currentProgram.getMemory().getInt(address);
	}

	/**
	 * Sets the 'integer' value at the specified address.
	 * @param address the address to set the 'integer'
	 * @param value the value to set
	 * @throws MemoryAccessException if memory does not exist or is uninitialized
	 */
	public final void setInt(Address address, int value) throws MemoryAccessException {
		currentProgram.getMemory().setInt(address, value);
	}

	/**
	 * Returns the 'long' value at the specified address in memory.
	 * @param address the address
	 * @return the 'long' value at the specified address in memory
	 * @throws MemoryAccessException if the memory is not readable
	 */
	public final long getLong(Address address) throws MemoryAccessException {
		return currentProgram.getMemory().getLong(address);
	}

	/**
	 * Sets the 'long' value at the specified address.
	 * @param address the address to set the 'long'
	 * @param value the value to set
	 * @throws MemoryAccessException if memory does not exist or is uninitialized
	 */
	public final void setLong(Address address, long value) throws MemoryAccessException {
		currentProgram.getMemory().setLong(address, value);
	}

	/**
	 * Returns the 'float' value at the specified address in memory.
	 * @param address the address
	 * @return the 'float' value at the specified address in memory
	 * @throws MemoryAccessException if the memory is not readable
	 */
	public final float getFloat(Address address) throws MemoryAccessException {
		int bits = currentProgram.getMemory().getInt(address);
		return Float.intBitsToFloat(bits);
	}

	/**
	 * Sets the 'float' value at the specified address.
	 * @param address the address to set the 'float'
	 * @param value the value to set
	 * @throws MemoryAccessException if memory does not exist or is uninitialized
	 */
	public final void setFloat(Address address, float value) throws MemoryAccessException {
		int bits = Float.floatToIntBits(value);
		currentProgram.getMemory().setInt(address, bits);
	}

	/**
	 * Returns the 'double' value at the specified address in memory.
	 * @param address the address
	 * @return the 'double' value at the specified address in memory
	 * @throws MemoryAccessException if the memory is not readable
	 */
	public final double getDouble(Address address) throws MemoryAccessException {
		long bits = currentProgram.getMemory().getLong(address);
		return Double.longBitsToDouble(bits);
	}

	/**
	 * Sets the 'double' value at the specified address.
	 * @param address the address to set the 'double'
	 * @param value the value to set
	 * @throws MemoryAccessException if memory does not exist or is uninitialized
	 */
	public final void setDouble(Address address, double value) throws MemoryAccessException {
		long bits = Double.doubleToLongBits(value);
		currentProgram.getMemory().setLong(address, bits);
	}

	/**
	 * Returns an array of the references FROM the given address.
	 * @param address the from address of the references
	 * @return an array of the references FROM the given address
	 */
	public final Reference[] getReferencesFrom(Address address) {
		return currentProgram.getReferenceManager().getReferencesFrom(address);
	}

	/**
	 * Returns an array of the references TO the given address.
	 * Note: If more than 4096 references exists to this address,
	 * only the first 4096 will be returned.
	 * If you need to access all the references, please
	 * refer to the method <code>ReferenceManager::getReferencesTo(Address)</code>.
	 * @param address the from address of the references
	 * @return an array of the references TO the given address
	 */
	public final Reference[] getReferencesTo(Address address) {
		int count = currentProgram.getReferenceManager().getReferenceCountTo(address);
		if (count > MAX_REFERENCES_TO) {
			count = MAX_REFERENCES_TO;
		}
		int index = 0;
		Reference[] references = new Reference[count];
		ReferenceIterator iterator = currentProgram.getReferenceManager().getReferencesTo(address);
		while (iterator.hasNext()) {
			monitor.setMessage("Loading references to " + address + ": " + index + " of " + count);
			if (monitor.isCancelled() || index == MAX_REFERENCES_TO) {
				break;
			}
			references[index++] = iterator.next();
		}
		return references;
	}

	/**
	 * Returns the reference from the instruction to the given address.
	 * @param instruction the instruction
	 * @param toAddress the destination address
	 * @return the reference from the instruction to the given address
	 */
	public final Reference getReference(Instruction instruction, Address toAddress) {
		Reference[] references =
			currentProgram.getReferenceManager().getReferencesFrom(instruction.getMinAddress());
		for (Reference reference : references) {
			if (reference.getToAddress().equals(toAddress)) {
				return reference;
			}
		}
		return null;
	}

	/**
	 * Returns the reference from the data to the given address.
	 * @param data the data
	 * @param toAddress the destination address
	 * @return the reference from the data to the given address
	 */
	public final Reference getReference(Data data, Address toAddress) {
		Reference[] references =
			currentProgram.getReferenceManager().getReferencesFrom(data.getMinAddress());
		for (Reference reference : references) {
			if (reference.getToAddress().equals(toAddress)) {
				return reference;
			}
		}
		return null;
	}

	/**
	 * Creates a memory reference from the given instruction.
	 * @param instruction the instruction
	 * @param operandIndex the operand index on the instruction
	 * @param toAddress the TO address
	 * @param flowType the flow type of the reference
	 * @return the newly created memory reference
	 */
	public final Reference createMemoryReference(Instruction instruction, int operandIndex,
			Address toAddress, RefType flowType) {
		ReferenceManager referenceManager = currentProgram.getReferenceManager();
		Reference ref = referenceManager.addMemoryReference(instruction.getMinAddress(), toAddress,
			flowType, SourceType.USER_DEFINED, operandIndex);
		return ref;
	}

	/**
	 * Creates a memory reference from the given data.
	 * @param data the data
	 * @param toAddress the TO address
	 * @param dataRefType the type of the reference
	 * @return the newly created memory reference
	 */
	public final Reference createMemoryReference(Data data, Address toAddress,
			RefType dataRefType) {
		ReferenceManager referenceManager = currentProgram.getReferenceManager();
		Reference ref = referenceManager.addMemoryReference(data.getMinAddress(), toAddress,
			dataRefType, SourceType.USER_DEFINED, 0);
		return ref;
	}

	/**
	 * Creates an external reference from the given instruction.
	 * For instructions with flow, the FlowType will be assumed, otherwise
	 * {@link RefType#DATA} will be assumed.  To specify the appropriate
	 * RefType use the alternate form of this method.
	 * @param instruction the instruction
	 * @param operandIndex the operand index on the instruction
	 * @param libraryName the name of the library being referred
	 * @param externalLabel the name of function in the library being referred
	 * @param externalAddr the address of the function in the library being referred
	 * @return the newly created external reference
	 * @throws Exception if an exception occurs
	 */
	public final Reference createExternalReference(Instruction instruction, int operandIndex,
			String libraryName, String externalLabel, Address externalAddr) throws Exception {

		// Use inferred reference type
		RefType refType = RefType.DATA;
		FlowType flowType = instruction.getFlowType();
		if (flowType.isComputed()) {
			if (flowType.isCall()) {
				refType = RefType.COMPUTED_CALL;
			}
			else if (flowType.isJump()) {
				refType = RefType.COMPUTED_JUMP;
			}
		}
		else if (flowType.isCall()) {
			refType = RefType.UNCONDITIONAL_CALL;
		}
		else if (flowType.isJump()) {
			refType = RefType.UNCONDITIONAL_JUMP;
		}

		return createExternalReference(instruction, operandIndex, libraryName, externalLabel,
			externalAddr, refType);
	}

	/**
	 * Creates an external reference from the given instruction.
	 * @param instruction the instruction
	 * @param operandIndex the operand index on the instruction
	 * @param libraryName the name of the library being referred
	 * @param externalLabel the name of function in the library being referred
	 * @param externalAddr the address of the function in the library being referred
	 * @param refType the appropriate external reference type (e.g., DATA, COMPUTED_CALL, etc.)
	 * @return the newly created external reference
	 * @throws Exception if an exception occurs
	 */
	public final Reference createExternalReference(Instruction instruction, int operandIndex,
			String libraryName, String externalLabel, Address externalAddr, RefType refType)
			throws Exception {
		ReferenceManager referenceManager = currentProgram.getReferenceManager();
		Reference reference =
			referenceManager.addExternalReference(instruction.getMinAddress(), libraryName,
				externalLabel, externalAddr, SourceType.USER_DEFINED, operandIndex, refType);
		return reference;
	}

	/**
	 * Creates an external reference from the given data.  The reference type {@link RefType#DATA}
	 * will be used.
	 * @param data the data
	 * @param libraryName the name of the library being referred
	 * @param externalLabel the name of function in the library being referred
	 * @param externalAddr the address of the function in the library being referred
	 * @return the newly created external reference
	 * @throws Exception if an exception occurs
	 */
	public final Reference createExternalReference(Data data, String libraryName,
			String externalLabel, Address externalAddr) throws Exception {
		ReferenceManager referenceManager = currentProgram.getReferenceManager();
		Reference reference = referenceManager.addExternalReference(data.getMinAddress(),
			libraryName, externalLabel, externalAddr, SourceType.USER_DEFINED, 0, RefType.DATA);
		return reference;
	}

	/**
	 * Create a stack reference from the given instruction
	 * @param instruction the instruction
	 * @param operandIndex the operand index on the instruction
	 * @param stackOffset the stack offset of the reference
	 * @param isWrite true if the reference is WRITE access or false if the
	 * reference is READ access
	 * @return the newly created stack reference
	 */
	public final Reference createStackReference(Instruction instruction, int operandIndex,
			int stackOffset, boolean isWrite) {
		ReferenceManager referenceManager = currentProgram.getReferenceManager();
		RefType type = isWrite ? RefType.WRITE : RefType.READ;
		Reference ref = referenceManager.addStackReference(instruction.getMinAddress(),
			operandIndex, stackOffset, type, SourceType.USER_DEFINED);
		return ref;
	}

	/**
	 * Removes the given reference.
	 * @param reference the reference to remove
	 */
	public final void removeReference(Reference reference) {
		currentProgram.getReferenceManager().delete(reference);
	}

	/**
	 * Sets the given reference as primary.
	 * @param reference the reference to mark as primary
	 */
	public final void setReferencePrimary(Reference reference) {
		currentProgram.getReferenceManager().setPrimary(reference, true);
	}

	/**
	 * Sets the given reference as primary.
	 * @param reference the reference
	 * @param primary true if primary, false not primary
	 */
	public final void setReferencePrimary(Reference reference, boolean primary) {
		currentProgram.getReferenceManager().setPrimary(reference, primary);
	}

	/**
	 * Creates a new equate on the scalar value
	 * at the operand index of the instruction.
	 * @param instruction the instruction
	 * @param operandIndex the operand index on the instruction
	 * @param equateName the name of the equate
	 * @return the newly created equate
	 * @throws Exception if a scalar does not exist of the specified
	 * operand index of the instruction
	 */
	public final Equate createEquate(Instruction instruction, int operandIndex, String equateName)
			throws Exception {
		Object[] operandObject = instruction.getOpObjects(operandIndex);
		for (Object object : operandObject) {
			if (object instanceof Scalar) {
				Scalar scalar = (Scalar) object;
				long scalarValue = scalar.getUnsignedValue();
				Equate equate =
					currentProgram.getEquateTable().createEquate(equateName, scalarValue);
				equate.addReference(instruction.getMinAddress(), operandIndex);
				return equate;
			}
		}
		throw new InvalidInputException(
			"Unable to create equate on non-scalar instruction operand at " +
				instruction.getMinAddress());
	}

	/**
	 * Creates a new equate on the scalar value
	 * at the value of the data.
	 * @param data the data
	 * @param equateName the name of the equate
	 * @return the newly created equate
	 * @throws InvalidInputException if a scalar does not exist on the data
	 */
	public final Equate createEquate(Data data, String equateName) throws Exception {
		Object value = data.getValue();
		if (value instanceof Scalar) {
			Scalar scalar = (Scalar) value;
			long scalarValue = scalar.getUnsignedValue();
			Equate equate = currentProgram.getEquateTable().createEquate(equateName, scalarValue);
			equate.addReference(data.getMinAddress(), 0);
			return equate;
		}
		throw new InvalidInputException(
			"Unable to create equate on non-scalar value at " + data.getMinAddress());
	}

	/**
	 * Returns the equate defined at the operand index of the instruction.
	 * @param instruction the instruction
	 * @param operandIndex the operand index
	 * @return the equate defined at the operand index of the instruction
	 * @deprecated this form of getEquate is not supported and will throw a UnsupportedOperationException
	 */
	@Deprecated
	public final Equate getEquate(Instruction instruction, int operandIndex) {
		throw new UnsupportedOperationException("this form of getEquate is unsupported");
	}

	/**
	 * Returns the equate defined at the operand index of the instruction with the given value.
	 * @param instruction the instruction
	 * @param operandIndex the operand index
	 * @param value scalar equate value
	 * @return the equate defined at the operand index of the instruction
	 */
	public final Equate getEquate(Instruction instruction, int operandIndex, long value) {
		return currentProgram.getEquateTable()
				.getEquate(instruction.getMinAddress(), operandIndex,
					value);
	}

	/**
	 * Returns the equates defined at the operand index of the instruction.
	 * @param instruction the instruction
	 * @param operandIndex the operand index
	 * @return the equate defined at the operand index of the instruction
	 */
	public final List<Equate> getEquates(Instruction instruction, int operandIndex) {
		return currentProgram.getEquateTable()
				.getEquates(instruction.getMinAddress(),
					operandIndex);
	}

	/**
	 * Returns the equate defined on the data.
	 * @param data the data
	 * @return the equate defined on the data
	 */
	public final Equate getEquate(Data data) {
		Object obj = data.getValue();
		if (obj instanceof Scalar) {
			return currentProgram.getEquateTable()
					.getEquate(data.getMinAddress(), 0,
						((Scalar) obj).getValue());
		}
		return null;
	}

	/**
	 * Removes the equate defined at the operand index of the instruction.
	 * @param instruction the instruction
	 * @param operandIndex the operand index
	 * @deprecated this form of getEquate is not supported and will throw a UnsupportedOperationException
	 */
	@Deprecated
	public final void removeEquate(Instruction instruction, int operandIndex) {
		throw new UnsupportedOperationException("this form of removeEquate is unsupported");
	}

	/**
	 * Removes the equate defined at the operand index of the instruction with the given value.
	 * @param instruction the instruction
	 * @param operandIndex the operand index
	 * @param value scalar value corresponding to equate
	 */
	public final void removeEquate(Instruction instruction, int operandIndex, long value) {
		Address address = instruction.getMinAddress();
		Equate equate = currentProgram.getEquateTable().getEquate(address, operandIndex, value);
		equate.removeReference(address, operandIndex);
		if (equate.getReferenceCount() == 0) {
			currentProgram.getEquateTable().removeEquate(equate.getName());
		}
	}

	/**
	 * Removes the equates defined at the operand index of the instruction.
	 * @param instruction the instruction
	 * @param operandIndex the operand index
	 */
	public final void removeEquates(Instruction instruction, int operandIndex) {
		Address address = instruction.getMinAddress();
		List<Equate> equates = currentProgram.getEquateTable().getEquates(address, operandIndex);
		for (Equate equate : equates) {
			equate.removeReference(address, operandIndex);
			if (equate.getReferenceCount() == 0) {
				if (equate.getReferenceCount() == 0) {
					currentProgram.getEquateTable().removeEquate(equate.getName());
				}
			}
		}
	}

	/**
	 * Removes the equate defined on the data.
	 * @param data the data
	 */
	public final void removeEquate(Data data) {
		Address address = data.getMinAddress();
		List<Equate> equates = currentProgram.getEquateTable().getEquates(address, 0);
		for (Equate equate : equates) {
			equate.removeReference(address, 0);
			if (equate.getReferenceCount() == 0) {
				if (equate.getReferenceCount() == 0) {
					currentProgram.getEquateTable().removeEquate(equate.getName());
				}
			}
		}
	}

	/**
	 * Creates a <code>NOTE</code> bookmark at the specified address
	 * <br>
	 * NOTE: if a <code>NOTE</code> bookmark already exists at the address, it will be replaced.
	 * This is intentional and is done to match the behavior of setting bookmarks from the UI.
	 * 
	 * @param address  the address to create the bookmark
	 * @param category the bookmark category (it may be null)
	 * @param note  the bookmark text
	 * @return the newly created bookmark
	 */
	public final Bookmark createBookmark(Address address, String category, String note) {

		// enforce one bookmark per address, as this is what the UI does
		Bookmark[] existingBookmarks = getBookmarks(address);
		if (existingBookmarks != null && existingBookmarks.length > 0) {
			existingBookmarks[0].set(category, note);
			return existingBookmarks[0];
		}

		BookmarkManager bkm = currentProgram.getBookmarkManager();
		return bkm.setBookmark(address, BookmarkType.NOTE, category, note);
	}

	/**
	 * Returns all of the NOTE bookmarks defined at the specified address
	 * @param address the address to retrieve the bookmark
	 * @return the bookmarks at the specified address
	 */
	public final Bookmark[] getBookmarks(Address address) {
		return currentProgram.getBookmarkManager().getBookmarks(address, BookmarkType.NOTE);
	}

	/**
	 * Removes the specified bookmark.
	 * @param bookmark the bookmark to remove
	 */
	public final void removeBookmark(Bookmark bookmark) {
		currentProgram.getBookmarkManager().removeBookmark(bookmark);
	}

	/**
	 * Opens a Data Type Archive
	 * @param archiveFile the archive file to open
	 * @param readOnly should file be opened read only
	 */
	public final FileDataTypeManager openDataTypeArchive(File archiveFile, boolean readOnly)
			throws Exception {
		FileDataTypeManager dtfm = FileDataTypeManager.openFileArchive(archiveFile, !readOnly);
		return dtfm;
	}

	/**
	 * Saves the changes to the specified program.
	 * If the program does not already exist in the current project
	 * then it will be saved into the root folder.
	 * If a program already exists with the specified
	 * name, then a time stamp will be appended to the name to make it unique.
	 * @param program the program to save
	 * @throws Exception
	 */
	public void saveProgram(Program program) throws Exception {
		saveProgram(program, null);
	}

	/**
	 * Saves changes to the specified program.
	 * <p>
	 * If the program does not already exist in the current project
	 * then it will be saved into a project folder path specified by the path parameter.
	 * <p>
	 * If path is NULL, the program will be saved into the root folder.  If parts of the path are
	 * missing, they will be created if possible.
	 * <p>
	 * If a program already exists with the specified name, then a time stamp will be appended 
	 * to the name to make it unique.
	 * <p>
	 * @param program the program to save
	 * @param path list of string path elements (starting at the root of the project) that specify 
	 * the project folder to save the program info.  Example: { "folder1", "subfolder2", "finalfolder" }
	 * @throws Exception
	 */
	public void saveProgram(Program program, List<String> path) throws Exception {
		if (program == null) {
			return;
		}
		if (program.getDomainFile().isInWritableProject()) {
			if (program == currentProgram) {
				end(true);
			}
			try {
				program.save(getClass().getName(), monitor);
			}
			finally {
				if (program == currentProgram) {
					start();
				}
			}
			return;
		}
		DomainFolder folder = getProjectRootFolder();
		if (path != null) {
			for (String folderName : path) {
				if (folderName == null || folderName.isEmpty()) {
					continue;
				}
				DomainFolder existingFolder = folder.getFolder(folderName);
				if (existingFolder == null) {
					folder = folder.createFolder(folderName);
				}
				else {
					folder = existingFolder;
				}
			}
		}
		if (program == currentProgram) {
			end(true);//end the current open transaction, so that we can save...
		}
		try {
			folder.createFile(program.getName(), program, monitor);
		}
		catch (DuplicateFileException e) {
			SimpleDateFormat formatter = new SimpleDateFormat("dd.MMM.yyyy_HH.mm.ss");
			String time = formatter.format(new Date());
			folder.createFile(program.getName() + "_" + time, program, monitor);
		}
		finally {
			if (program == currentProgram) {
				start();//start a new transaction, now that save is done...
			}
		}
		monitor.setCancelEnabled(true);
		folder.setActive();//makes the data tree expand to show new file!
	}

	/**
	 * This method looks up the current project and returns
	 * the root domain folder.
	 * @return the root domain folder of the current project
	 */
	public DomainFolder getProjectRootFolder() {
		Project project = AppInfo.getActiveProject();
		ProjectData projectData = project.getProjectData();
		DomainFolder folder = projectData.getRootFolder();
		return folder;
	}

	/**
	 *
	 * @param type
	 * @param text
	 * @return
	 */
	private Address findComment(int type, String text) {
		Listing listing = currentProgram.getListing();
		Memory memory = currentProgram.getMemory();
		AddressIterator iter = listing.getCommentAddressIterator(type, memory, true);
		while (iter.hasNext() && !monitor.isCancelled()) {
			Address addr = iter.next();
			String plate = listing.getComment(type, addr);
			if (plate.indexOf(text) >= 0) {
				return addr;
			}
		}
		return null;
	}
}
