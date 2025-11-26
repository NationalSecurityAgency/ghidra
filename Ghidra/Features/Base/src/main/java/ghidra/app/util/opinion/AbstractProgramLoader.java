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

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import ghidra.app.plugin.processors.generic.MemoryBlockDefinition;
import ghidra.app.util.Option;
import ghidra.app.util.OptionUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.LockException;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.HashUtilities;
import ghidra.util.MD5Utilities;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * An abstract {@link Loader} that provides a framework to conveniently load {@link Program}s.
 * Subclasses are responsible for the actual load.
 * <p>
 * This {@link Loader} provides a couple processor-related options, as all {@link Program}s will
 * have a processor associated with them.
 */
public abstract class AbstractProgramLoader implements Loader {

	public static final String APPLY_LABELS_OPTION_NAME = "Apply Processor Defined Labels";
	public static final String ANCHOR_LABELS_OPTION_NAME = "Anchor Processor Defined Labels";

	/**
	 * Loads bytes in a particular format as a new {@link Loaded} {@link Program}. Multiple
	 * {@link Program}s may end up getting created, depending on the nature of the format.
	 * <p>
	 * Note that when the load completes, the returned {@link Loaded} {@link Program}s are not 
	 * saved to a project.  That is the responsibility of the caller (see 
	 * {@link Loaded#save(TaskMonitor)}).
	 * <p>
	 * It is also the responsibility of the caller to close the returned {@link Loaded} 
	 * {@link Program}s with {@link Loaded#close()} when they are no longer needed.
	 *
	 * @param settings The {@link Loader.ImporterSettings}.
	 * @return A {@link List} of one or more {@link Loaded} {@link Program}s (created but not 
	 *   saved).
	 * @throws LoadException if the load failed in an expected way.
	 * @throws IOException if there was an IO-related problem loading.
	 * @throws CancelledException if the user cancelled the load.
	 */
	protected abstract List<Loaded<Program>> loadProgram(ImporterSettings settings)
			throws IOException, LoadException, CancelledException;

	/**
	 * Loads program bytes into the specified {@link Program}.  This method will not create any new
	 * {@link Program}s.  It is only for adding to an existing {@link Program}.
	 * <p>
	 * NOTE: The loading that occurs in this method will automatically be done in a transaction.
	 *
	 * @param program The {@link Program} to load into.
	 * @param settings The {@link Loader.ImporterSettings}.
	 * @throws LoadException if the load failed in an expected way.
	 * @throws IOException if there was an IO-related problem loading.
	 * @throws CancelledException if the user cancelled the load.
	 */
	protected abstract void loadProgramInto(Program program, ImporterSettings settings)
			throws IOException, LoadException, CancelledException;

	@Override
	public final LoadResults<? extends DomainObject> load(ImporterSettings settings)
			throws IOException, CancelledException, VersionException, LoadException {

		if (!settings.loadSpec().isComplete()) {
			throw new LoadException("Load spec is incomplete");
		}

		List<Loaded<Program>> loadedPrograms = loadProgram(settings);

		boolean success = false;
		try {
			for (Loaded<Program> loadedProgram : loadedPrograms) {
				settings.monitor().checkCancelled();
				Program program = loadedProgram.getDomainObject(this);
				try {
					applyProcessorLabels(settings.options(), program);
					program.setEventsEnabled(true);
				}
				finally {
					program.release(this);
				}
			}

			// Subclasses can perform custom post-load fix-ups
			postLoadProgramFixups(loadedPrograms, settings);

			// Discard temporary programs
			Iterator<Loaded<Program>> iter = loadedPrograms.iterator();
			while (iter.hasNext()) {
				Loaded<Program> loaded = iter.next();
				if (loaded.check(p -> p.isTemporary())) {
					iter.remove();
					loaded.close();
				}
			}

			success = true;
			return new LoadResults<Program>(loadedPrograms);
		}
		finally {
			if (!success) {
				loadedPrograms.forEach(Loaded::close);
			}
			postLoadCleanup(success);
		}
	}

	@Override
	public final void loadInto(Program program, ImporterSettings settings)
			throws IOException, LoadException, CancelledException {

		if (!settings.loadSpec().isComplete()) {
			throw new LoadException("Load spec is incomplete");
		}

		program.setEventsEnabled(false);
		int transactionID = program.startTransaction("Loading - " + getName());
		boolean success = false;
		try {
			loadProgramInto(program, settings);
			success = true;
		}
		finally {
			program.endTransaction(transactionID, success);
			program.setEventsEnabled(true);
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
		ArrayList<Option> list = new ArrayList<>();
		list.add(new Option(APPLY_LABELS_OPTION_NAME, shouldApplyProcessorLabelsByDefault(),
			Boolean.class, Loader.COMMAND_LINE_ARG_PREFIX + "-applyLabels"));
		list.add(new Option(ANCHOR_LABELS_OPTION_NAME, true, Boolean.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-anchorLabels"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		if (options != null) {
			for (Option option : options) {
				String name = option.getName();
				if (name.equals(APPLY_LABELS_OPTION_NAME) ||
					name.equals(ANCHOR_LABELS_OPTION_NAME)) {
					if (!Boolean.class.isAssignableFrom(option.getValueClass())) {
						return "Invalid type for option: " + name + " - " + option.getValueClass();
					}
				}
			}
		}
		return null;
	}

	/**
	 * This gets called after the given list of {@link Loaded loaded programs}s is finished loading.
	 * It provides subclasses an opportunity to do follow-on actions to the load.
	 *
	 * @param loadedPrograms The {@link Loaded loaded programs} to be fixed up.
	 * @param settings The {@link Loader.ImporterSettings}.
	 * @throws IOException if there was an IO-related problem loading.
	 * @throws CancelledException if the user cancelled the load.
	 */
	protected void postLoadProgramFixups(List<Loaded<Program>> loadedPrograms,
			ImporterSettings settings) throws CancelledException, IOException {
		// Default behavior is to do nothing
	}

	/**
	 * This gets called as the final step of the load process.  Subclasses may override it to ensure
	 * any resources they created can be cleaned up after the load finishes.
	 * <p>
	 * NOTE: Subclasses should not use this method to release any {@link Program}s they created when
	 * failure occurs. That should be done by the subclass as soon as it detects failure has
	 * occurred.
	 * 
	 * @param success True if the load completed successfully; otherwise, false
	 */
	protected void postLoadCleanup(boolean success) {
		// Default behavior is to do nothing
	}

	/**
	 * Returns whether or not processor labels should be applied by default.  Most loaders will
	 * not need to override this method because they will not want the labels applied by default.
	 *
	 * @return Whether or not processor labels should be applied by default.
	 */
	protected boolean shouldApplyProcessorLabelsByDefault() {
		return false;
	}

	/**
	 * Generates a block name.
	 *
	 * @param program The {@link Program} for the block.
	 * @param isOverlay true if the block is an overlay; use "ov" in the name.
	 * @param space The {@link AddressSpace} for the block.
	 * @return The generated block name.
	 */
	protected String generateBlockName(Program program, boolean isOverlay, AddressSpace space) {
		if (!isOverlay) {
			return space.getName();
		}
		AddressFactory factory = program.getAddressFactory();
		int count = 0;
		while (count < 1000) {
			String lname = "ov" + (++count);
			if (factory.getAddressSpace(lname) == null) {
				return lname;
			}
		}
		return "ov" + System.currentTimeMillis(); // CAN'T HAPPEN
	}

	/**
	 * Creates a {@link Program} with the specified attributes.
	 *
	 * @param imageBase  The image base address of the {@link Program}.
	 * @param settings The {@link Loader.ImporterSettings}.
	 * @return The newly created {@link Program}.
	 * @throws IOException if there was an IO-related problem with creating the {@link Program}.
	 */
	protected Program createProgram(Address imageBase, ImporterSettings settings)
			throws IOException {

		LanguageCompilerSpecPair pair = settings.loadSpec().getLanguageCompilerSpec();
		Language language = getLanguageService().getLanguage(pair.languageID);
		CompilerSpec compilerSpec = language.getCompilerSpecByID(pair.compilerSpecID);

		String programName =
			getProgramNameFromSourceData(settings.provider(), settings.importNameOnly());
		Program prog = new ProgramDB(programName, language, compilerSpec, settings.consumer());
		prog.setEventsEnabled(false);
		int id = prog.startTransaction("Set program properties");
		boolean success = false;
		try {
			setProgramProperties(prog, settings.provider(), getName());
			try {
				if (shouldSetImageBase(prog, imageBase)) {
					prog.setImageBase(imageBase, true);
				}
				success = true;
				return prog;
			}
			catch (LockException | AddressOverflowException e) {
				// shouldn't ever happen here
				throw new IOException(e);
			}
		}
		finally {
			prog.endTransaction(id, true); // More efficient to commit when program will be discarded
			if (!success) {
				prog.release(settings.consumer());
			}
		}
	}

	/**
	 * Creates a {@link Program} with the specified attributes at the {@link LoadSpec}'s desired 
	 * image base
	 *
	 * @param settings The {@link Loader.ImporterSettings}.
	 * @return The newly created {@link Program}.
	 * @throws IOException if there was an IO-related problem with creating the {@link Program}.
	 */
	protected Program createProgram(ImporterSettings settings) throws IOException {

		Address imageBaseAddr = getLanguageService()
				.getLanguage(settings.loadSpec().getLanguageCompilerSpec().languageID)
				.getAddressFactory()
				.getDefaultAddressSpace()
				.getAddress(settings.loadSpec().getDesiredImageBase());

		return createProgram(imageBaseAddr, settings);
	}

	/**
	 * Sets a program's Executable Path, Executable Format, MD5, SHA256, and FSRL properties.
	 *  
	 * @param prog {@link Program} (with active transaction)
	 * @param provider {@link ByteProvider} that the program was created from
	 * @param executableFormatName executable format string
	 * @throws IOException if error reading from ByteProvider
	 */
	public static void setProgramProperties(Program prog, ByteProvider provider,
			String executableFormatName) throws IOException {
		prog.setExecutablePath(provider.getAbsolutePath());
		if (executableFormatName != null) {
			prog.setExecutableFormat(executableFormatName);
		}
		FSRL fsrl = provider.getFSRL();
		String md5 =
			(fsrl != null && fsrl.getMD5() != null) ? fsrl.getMD5() : computeBinaryMD5(provider);
		if (fsrl != null) {
			if (fsrl.getMD5() == null) {
				fsrl = fsrl.withMD5(md5);
			}
			FSRL.writeToProgramInfo(prog, fsrl);
		}
		prog.setExecutableMD5(md5);
		String sha256 = computeBinarySHA256(provider);
		prog.setExecutableSHA256(sha256);
	}

	private String getProgramNameFromSourceData(ByteProvider provider, String domainFileName) {
		FSRL fsrl = provider.getFSRL();
		if (fsrl != null) {
			return fsrl.getName();
		}

		// If the ByteProvider doesn't have an FSRL, use the given domainFileName
		return domainFileName;
	}

	/**
	 * Creates default memory blocks for the given {@link Program}.
	 *
	 * @param program The {@link Program} to create default memory blocks for.
	 * @param settings The {@link Loader.ImporterSettings}.
	 */
	protected void createDefaultMemoryBlocks(Program program, ImporterSettings settings) {
		MessageLog log = settings.log();
		int id = program.startTransaction("Create default blocks");
		try {
			LanguageCompilerSpecPair pair = settings.loadSpec().getLanguageCompilerSpec();
			Language language = getLanguageService().getLanguage(pair.languageID);
			for (MemoryBlockDefinition blockDef : language.getDefaultMemoryBlocks()) {
				try {
					blockDef.createBlock(program);
				}
				catch (LockException e) {
					throw new AssertException("Unexpected Error");
				}
				catch (MemoryConflictException e) {
					log.appendMsg(
						"Failed to add language defined memory block due to conflict: " + blockDef);
				}
				catch (AddressOverflowException e) {
					log.appendMsg(
						"Failed to add language defined memory block due to address error " +
							blockDef);
					log.appendMsg(" >> " + e.getMessage());
				}
				catch (InvalidAddressException e) {
					log.appendMsg(
						"Failed to add language defined memory block due to invalid address: " +
							blockDef);
					log.appendMsg(" >> Processor specification error (pspec): " + e.getMessage());
				}
			}
		}
		catch (LanguageNotFoundException e) {
			log.appendMsg("Failed get language for: " +
				settings.loadSpec().getLanguageCompilerSpec().languageID);
		}
		finally {
			program.endTransaction(id, true);
		}
	}

	/**
	 * Mark this address as a function by creating a one byte function.  The single byte body
	 * function is picked up by the function analyzer, disassembled, and the body fixed.
	 * Marking the function this way keeps disassembly and follow on analysis out of the loaders.
	 * 
	 * @param program the program
	 * @param name name of function, null if name not known
	 * @param funcStart starting address of the function
	 */
	public static void markAsFunction(Program program, String name, Address funcStart) {
		FunctionManager functionMgr = program.getFunctionManager();

		if (functionMgr.getFunctionAt(funcStart) != null) {
			return;
		}
		try {
			functionMgr.createFunction(name, funcStart, new AddressSet(funcStart, funcStart),
				SourceType.IMPORTED);
		}
		catch (InvalidInputException e) {
			// ignore
		}
		catch (OverlappingFunctionException e) {
			// ignore
		}
	}

	/**
	 * Adds the {@link MemoryBlock#EXTERNAL_BLOCK_NAME EXERNAL block} to memory, or adds to an
	 * existing one
	 * 
	 * @param program The {@link Program}
	 * @param size The desired size of the new EXTERNAL block
	 * @param log The {@link MessageLog}
	 * @return The {@link Address} of the new (or new piece) of EXTERNAL block
	 * @throws Exception if there was an issue creating or adding to the EXTERNAL block
	 */
	public static Address addExternalBlock(Program program, long size, MessageLog log)
			throws Exception {
		Memory mem = program.getMemory();
		MemoryBlock externalBlock = mem.getBlock(MemoryBlock.EXTERNAL_BLOCK_NAME);
		Address ret;
		if (externalBlock != null) {
			ret = externalBlock.getEnd().add(1);
			MemoryBlock newBlock =
				mem.createBlock(externalBlock, MemoryBlock.EXTERNAL_BLOCK_NAME, ret, size);
			mem.join(externalBlock, newBlock);
		}
		else {
			ret = MachoProgramUtils.getNextAvailableAddress(program);
			externalBlock =
				mem.createUninitializedBlock(MemoryBlock.EXTERNAL_BLOCK_NAME, ret, size, false);
			externalBlock.setWrite(true);
			externalBlock.setArtificial(true);
			externalBlock.setComment(
				"NOTE: This block is artificial and is used to make relocations work correctly");
		}
		return ret;
	}

	/**
	 * Gets the {@link Loader}'s language service.
	 * <p>
	 * The default behavior of this method is to return the {@link DefaultLanguageService}.
	 *
	 * @return The {@link Loader}'s language service.
	 */
	protected LanguageService getLanguageService() {
		return DefaultLanguageService.getLanguageService();
	}

	private AddressSetView getProcessorDefinedMemoryBlockAddresses(Program program) {
		AddressSet blockAddrSet = new AddressSet();
		Memory memory = program.getMemory();
		Language language = program.getLanguage();
		for (MemoryBlockDefinition defaultMemoryBlockDef : language.getDefaultMemoryBlocks()) {
			MemoryBlock block = memory.getBlock(defaultMemoryBlockDef.getBlockName());
			if (block != null) {
				blockAddrSet.add(block.getAddressRange());
			}
		}
		return blockAddrSet;
	}

	private void applyProcessorLabels(List<Option> options, Program program) {
		int id = program.startTransaction("Finalize load");
		try {
			Language lang = program.getLanguage();
			// always create anchored symbols for memory mapped registers
			// which may be explicitly referenced by pcode
			for (Register reg : lang.getRegisters()) {
				Address addr = reg.getAddress();
				if (addr.isMemoryAddress()) {
					createSymbol(program, reg.getName(), addr, null, false, true, true);
				}
			}

			// NOTE: pspec defined labels should always be defined if they correspond to a memory
			// block defined by the pspec.
			boolean applyAllProcessorLabels = shouldApplyProcessorLabels(options);
			AddressSetView pspecDefinedBlockSet = getProcessorDefinedMemoryBlockAddresses(program);
			boolean anchorSymbols = shouldAnchorSymbols(options);
			List<AddressLabelInfo> labels = lang.getDefaultSymbols();
			for (AddressLabelInfo info : labels) {
				Address addr = info.getAddress();
				boolean isRequiredLabel = pspecDefinedBlockSet.contains(addr);
				if (isRequiredLabel || applyAllProcessorLabels) {
					// NOTE: Required labels contained within a pspec-defined memory block do not 
					// need to be pinned/anchored
					boolean anchor = !isRequiredLabel && anchorSymbols;
					createSymbol(program, info.getLabel(), info.getAddress(), info.getDescription(),
						info.isEntry(), info.isPrimary(), anchor);
				}
			}

			GhidraProgramUtilities.resetAnalysisFlags(program);
		}
		finally {
			program.endTransaction(id, true);
		}
	}

	private static void createSymbol(Program program, String labelname, Address address,
			String comment, boolean isEntry, boolean isPrimary, boolean anchorSymbols) {
		SymbolTable symTable = program.getSymbolTable();
		Address addr = address;
		Symbol s = symTable.getPrimarySymbol(addr);
		try {
			Namespace namespace = program.getGlobalNamespace();
			s = symTable.createLabel(addr, labelname, namespace, SourceType.IMPORTED);
			if (comment != null) {
				program.getListing().setComment(address, CommentType.EOL, comment);
			}
			if (isEntry) {
				symTable.addExternalEntryPoint(addr);
			}
			if (isPrimary) {
				s.setPrimary();
			}
			if (anchorSymbols) {
				s.setPinned(true);
			}
		}
		catch (InvalidInputException e) {
			// Nothing to do
		}
	}

	private static String computeBinaryMD5(ByteProvider provider) throws IOException {
		try (InputStream in = provider.getInputStream(0)) {
			return MD5Utilities.getMD5Hash(in);
		}
	}

	private static String computeBinarySHA256(ByteProvider provider) throws IOException {
		try (InputStream in = provider.getInputStream(0)) {
			return HashUtilities.getHash(HashUtilities.SHA256_ALGORITHM, in);
		}
	}

	private boolean shouldSetImageBase(Program prog, Address imageBase) {
		if (imageBase == null || imageBase instanceof SegmentedAddress) {
			return false;
		}
		return imageBase.getAddressSpace() == prog.getAddressFactory().getDefaultAddressSpace();
	}

	private boolean shouldApplyProcessorLabels(List<Option> options) {
		return OptionUtils.getBooleanOptionValue(APPLY_LABELS_OPTION_NAME, options, true);
	}

	private boolean shouldAnchorSymbols(List<Option> options) {
		return OptionUtils.getBooleanOptionValue(ANCHOR_LABELS_OPTION_NAME, options, true);
	}
}
