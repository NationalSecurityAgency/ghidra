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
package ghidra.trace.database;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;

import db.Transaction;
import db.DBHandle;
import generic.theme.GThemeDefaults.Colors.Messages;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.trace.TraceSleighUtils;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.util.DefaultLanguageService;
import ghidra.trace.database.bookmark.*;
import ghidra.trace.database.listing.*;
import ghidra.trace.database.memory.DBTraceMemoryManager;
import ghidra.trace.database.symbol.DBTraceReference;
import ghidra.trace.database.thread.DBTraceThreadManager;
import ghidra.trace.model.*;
import ghidra.trace.model.guest.TraceGuestPlatform;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.symbol.TraceReferenceManager;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.Msg;
import ghidra.util.database.DBOpenMode;
import ghidra.util.exception.*;
import ghidra.util.task.ConsoleTaskMonitor;

/**
 * A convenient means of creating a {@link Trace} for testing
 * 
 * <p>
 * There are two patterns for using this: 1) {@code try-with-resources}, and 2) in set up and tear
 * down. Some of our abstract test cases include one of these already. The constructors can build or
 * take a trace from a variety of sources, and it provides many methods for accessing parts of the
 * trace and/or program API more conveniently, esp., for generating addresses.
 * 
 * <p>
 * The builder is a consumer of the trace and will automatically release it in {@link #close()}.
 */
public class ToyDBTraceBuilder implements AutoCloseable {
	public final Language language;
	public final DBTrace trace;
	public final TracePlatform host;
	public final LanguageService languageService = DefaultLanguageService.getLanguageService();

	/**
	 * Open a .gzf compressed trace
	 * 
	 * @param file the .gzf file containing the trace
	 * @throws CancelledException never, since the monitor cannot be cancelled
	 * @throws VersionException if the trace's version is not as expected
	 * @throws LanguageNotFoundException if the trace's language cannot be found
	 * @throws IOException if there's an issue accessing the file
	 */
	public ToyDBTraceBuilder(File file)
			throws CancelledException, VersionException, LanguageNotFoundException, IOException {
		DBHandle handle = new DBHandle(file);
		this.trace = new DBTrace(handle, DBOpenMode.UPDATE, new ConsoleTaskMonitor(), this);
		this.language = trace.getBaseLanguage();
		this.host = trace.getPlatformManager().getHostPlatform();
	}

	/**
	 * Create a new trace with the given name and language
	 * 
	 * @param name the name
	 * @param langID the id of the language, as in {@link LanguageID}
	 * @throws IOException if there's an issue creating the trace's database file(s)
	 */
	// TODO: A constructor for specifying compiler, too
	public ToyDBTraceBuilder(String name, String langID) throws IOException {
		this.language = languageService.getLanguage(new LanguageID(langID));
		this.trace = new DBTrace(name, language.getDefaultCompilerSpec(), this);
		this.host = trace.getPlatformManager().getHostPlatform();
	}

	/**
	 * Adopt the given trace
	 * 
	 * <p>
	 * The builder will add itself as a consumer of the trace, so the caller may safely release it.
	 * 
	 * @param trace the trace
	 */
	public ToyDBTraceBuilder(Trace trace) {
		this.language = trace.getBaseLanguage();
		this.trace = (DBTrace) trace;
		this.host = trace.getPlatformManager().getHostPlatform();
		trace.addConsumer(this);
	}

	/**
	 * Manipulate the trace's memory and registers using Sleigh
	 * 
	 * @param snap the snap to modify
	 * @param thread the thread to modify, can be {@code null} if only memory is used
	 * @param frame the frame to modify
	 * @param sleigh the Sleigh source
	 */
	public void exec(long snap, TraceThread thread, int frame, String sleigh) {
		PcodeProgram program = SleighProgramCompiler.compileProgram((SleighLanguage) language,
			"builder", sleigh, PcodeUseropLibrary.nil());
		TraceSleighUtils.buildByteExecutor(trace, snap, thread, frame)
				.execute(program, PcodeUseropLibrary.nil());
	}

	/**
	 * Manipulate the trace's memory and registers using Sleigh
	 * 
	 * @param platform the platform whose language to use
	 * @param snap the snap to modify
	 * @param thread the thread to modify, can be {@code null} if only memory is used
	 * @param frame the frame to modify
	 * @param sleigh the lines of Sleigh, including semicolons.
	 */
	public void exec(TracePlatform platform, long snap, TraceThread thread, int frame,
			String sleigh) {
		TraceSleighUtils.buildByteExecutor(platform, snap, thread, frame)
				.execute(
					SleighProgramCompiler.compileProgram((SleighLanguage) platform.getLanguage(),
						"builder", sleigh, PcodeUseropLibrary.nil()),
					PcodeUseropLibrary.nil());
	}

	/**
	 * Get the named register
	 * 
	 * @param name the name
	 * @return the register or null if it doesn't exist
	 */
	public Register reg(String name) {
		return language.getRegister(name);
	}

	/**
	 * Get the named register
	 * 
	 * @param platform the platform
	 * @param name the name
	 * @return the register or null if it doesn't exist
	 */
	public Register reg(TracePlatform platform, String name) {
		return platform.getLanguage().getRegister(name);
	}

	/**
	 * A shortcut for {@code space.getAdddress(offset)}
	 * 
	 * @param space the space
	 * @param offset the offset
	 * @return the address
	 */
	public Address addr(AddressSpace space, long offset) {
		return space.getAddress(offset);
	}

	/**
	 * Create an address in the given language's default space
	 * 
	 * @param lang the language
	 * @param offset the offset
	 * @return the address
	 */
	public Address addr(Language lang, long offset) {
		return addr(lang.getDefaultSpace(), offset);
	}

	/**
	 * Create an address in the trace's default space
	 * 
	 * @param offset the offset
	 * @return the address
	 */
	public Address addr(long offset) {
		return addr(language, offset);
	}

	/**
	 * Create an address in the given platform's default space
	 * 
	 * @param platform the platform
	 * @param offset the offset
	 * @return the address
	 */
	public Address addr(TracePlatform platform, long offset) {
		return platform.getLanguage().getDefaultSpace().getAddress(offset);
	}

	/**
	 * Create an address in the given language's default data space
	 * 
	 * @param lang the language
	 * @param offset the offset
	 * @return the address
	 */
	public Address data(Language lang, long offset) {
		return addr(lang.getDefaultDataSpace(), offset);
	}

	/**
	 * Create an address in the trace's default data space
	 * 
	 * @param offset the offset
	 * @return the address
	 */
	public Address data(long offset) {
		return data(language, offset);
	}

	/**
	 * Create an address in the given platform's default data space
	 * 
	 * @param platform the platform
	 * @param offset the offset
	 * @return the address
	 */
	public Address data(TraceGuestPlatform platform, long offset) {
		return data(platform.getLanguage(), offset);
	}

	/**
	 * Create an address range: shortcut for {@link AddressRangeImpl}
	 * 
	 * @param start the start address
	 * @param end the end address
	 * @return the range
	 */
	public AddressRange range(Address start, Address end) {
		return new AddressRangeImpl(start, end);
	}

	/**
	 * Create an address range in the given space with the given start and end offsets
	 * 
	 * @param space the space
	 * @param start the start offset
	 * @param end the end offset
	 * @return the range
	 */
	public AddressRange range(AddressSpace space, long start, long end) {
		return range(addr(space, start), addr(space, end));
	}

	/**
	 * Create an address range in the given language's default space
	 * 
	 * @param lang the language
	 * @param start the start offset
	 * @param end the end offset
	 * @return the range
	 */
	public AddressRange range(Language lang, long start, long end) {
		return range(lang.getDefaultSpace(), start, end);
	}

	/**
	 * Create an address range in the trace's default space
	 * 
	 * @param start the start offset
	 * @param end the end offset
	 * @return the range
	 */
	public AddressRange range(long start, long end) {
		return range(language, start, end);
	}

	/**
	 * Create a singleton address range in the trace's default space
	 * 
	 * @param singleton the offset
	 * @return the range
	 */
	public AddressRange range(long singleton) {
		return range(singleton, singleton);
	}

	/**
	 * Create an address-span box in the trace's default space with a singleton snap
	 * 
	 * @param snap the snap
	 * @param start the start address offset
	 * @param end the end address offset
	 * @return the box
	 */
	public TraceAddressSnapRange srange(long snap, long start, long end) {
		return new ImmutableTraceAddressSnapRange(addr(start), addr(end), snap, snap);
	}

	/**
	 * Create an address range in the given language's default data space
	 * 
	 * @param lang the language
	 * @param start the start offset
	 * @param end the end offset
	 * @return the range
	 */
	public AddressRange drng(Language lang, long start, long end) {
		return range(language.getDefaultDataSpace(), start, end);
	}

	/**
	 * Create an address range in the trace's default data space
	 * 
	 * @param start the start offset
	 * @param end the end offset
	 * @return the range
	 */
	public AddressRange drng(long start, long end) {
		return drng(language, start, end);
	}

	/**
	 * Create an address range in the given platform's default space
	 * 
	 * @param platform the platform
	 * @param start the start offset
	 * @param end the end offset
	 * @return the range
	 */
	public AddressRange range(TracePlatform platform, long start, long end) {
		return range(platform.getLanguage(), start, end);
	}

	/**
	 * Create an address range in the given platform's default data space
	 * 
	 * @param platform the platform
	 * @param start the start offset
	 * @param end the end offset
	 * @return the range
	 */
	public AddressRange drng(TracePlatform platform, long start, long end) {
		return drng(platform.getLanguage(), start, end);
	}

	/**
	 * Create an address set from the given ranges
	 * 
	 * @param ranges the ranges
	 * @return the set
	 */
	public AddressSetView set(AddressRange... ranges) {
		AddressSet result = new AddressSet();
		for (AddressRange rng : ranges) {
			result.add(rng);
		}
		return result;
	}

	/**
	 * Create a byte array
	 * 
	 * <p>
	 * This is basically syntactic sugar, since expressing a byte array literal can get obtuse in
	 * Java. {@code new byte[] {0, 1, 2, (byte) 0x80, (byte) 0xff}} vs
	 * {@code arr(0, 1, 2, 0x80, 0xff)}.
	 * 
	 * @param e the bytes' values
	 * @return the array
	 */
	public byte[] arr(int... e) {
		byte[] result = new byte[e.length];
		for (int i = 0; i < e.length; i++) {
			result[i] = (byte) e[i];
		}
		return result;
	}

	/**
	 * Create a byte buffer
	 * 
	 * @param e the bytes' values
	 * @return the buffer, positioned at 0
	 */
	public ByteBuffer buf(int... e) {
		return ByteBuffer.wrap(arr(e));
	}

	/**
	 * Create a byte buffer, filled with a UTF-8 encoded string
	 * 
	 * @param str the string to encode
	 * @return the buffer, positioned at 0
	 */
	public ByteBuffer buf(String str) {
		CharsetEncoder ce = Charset.forName("UTF-8").newEncoder();
		ByteBuffer result =
			ByteBuffer.allocate(Math.round(ce.maxBytesPerChar() * str.length()) + 1);
		ce.encode(CharBuffer.wrap(str), result, true);
		result.put((byte) 0);
		return result.flip();
	}

	/**
	 * Start a transaction on the trace
	 * 
	 * <p>
	 * Use this in a {@code try-with-resources} block
	 * 
	 * @return the transaction handle
	 */
	public Transaction startTransaction() {
		return trace.openTransaction("Testing");
	}

	/**
	 * Ensure the given bookmark type exists and retrieve it
	 * 
	 * @param name the name of the type
	 * @return the type
	 */
	public DBTraceBookmarkType getOrAddBookmarkType(String name) {
		DBTraceBookmarkManager manager = trace.getBookmarkManager();
		return manager.defineBookmarkType(name, null, Messages.ERROR, 1);
	}

	/**
	 * Add a bookmark to the trace
	 * 
	 * @param snap the starting snap
	 * @param addr the address
	 * @param typeName the name of its type
	 * @param category the category
	 * @param comment an optional comment
	 * @return the new bookmark
	 */
	public DBTraceBookmark addBookmark(long snap, long addr, String typeName, String category,
			String comment) {
		DBTraceBookmarkType type = getOrAddBookmarkType(typeName);
		DBTraceBookmarkManager manager = trace.getBookmarkManager();
		DBTraceBookmark bm =
			manager.addBookmark(Lifespan.nowOn(snap), addr(addr), type, category, comment);
		assertNull(bm.getThread());
		assertEquals(snap, bm.getLifespan().lmin());
		assertEquals(addr(addr), bm.getAddress());
		assertEquals(typeName, bm.getTypeString());
		assertEquals(category, bm.getCategory());
		assertEquals(comment, bm.getComment());
		return bm;
	}

	/**
	 * Add a bookmark on a register in the trace
	 * 
	 * @param snap the starting snap
	 * @param threadName the name of the thread
	 * @param registerName the name of the register
	 * @param typeName the name of its type
	 * @param category the category
	 * @param comment an optional comment
	 * @return the new bookmark
	 */
	public DBTraceBookmark addRegisterBookmark(long snap, String threadName, String registerName,
			String typeName, String category, String comment) {
		Register register = language.getRegister(registerName);
		assertNotNull(register);
		TraceThread thread = getOrAddThread(threadName, snap);
		DBTraceBookmarkType type = getOrAddBookmarkType(typeName);
		DBTraceBookmarkManager manager = trace.getBookmarkManager();
		DBTraceBookmarkSpace space = manager.getBookmarkRegisterSpace(thread, true);
		DBTraceBookmark bm = (DBTraceBookmark) space.addBookmark(Lifespan.nowOn(snap), register,
			type, category, comment);
		assertSame(thread, bm.getThread());
		assertEquals(snap, bm.getLifespan().lmin());
		assertEquals(register.getAddress(), bm.getAddress());
		assertEquals(typeName, bm.getTypeString());
		assertEquals(category, bm.getCategory());
		return bm;
	}

	/**
	 * Create a data unit
	 * 
	 * @param snap the starting snap
	 * @param start the min address
	 * @param type the data type of the unit
	 * @param length the length, or -1 for the type's default
	 * @return the new data unit
	 * @throws CodeUnitInsertionException if the unit cannot be created
	 */
	public DBTraceDataAdapter addData(long snap, Address start, DataType type, int length)
			throws CodeUnitInsertionException {
		DBTraceCodeManager code = trace.getCodeManager();
		return code.definedData().create(Lifespan.nowOn(snap), start, type, length);
	}

	/**
	 * Create a data unit, first placing the given bytes
	 * 
	 * @param snap the starting snap
	 * @param start the min address
	 * @param type the data type of the unit
	 * @param buf the bytes to place, which will become the unit's bytes
	 * @return the new data unit
	 * @throws CodeUnitInsertionException if the unit cannot be created
	 */
	public DBTraceDataAdapter addData(long snap, Address start, DataType type, ByteBuffer buf)
			throws CodeUnitInsertionException {
		int length = buf.remaining();
		DBTraceMemoryManager memory = trace.getMemoryManager();
		memory.putBytes(snap, start, buf);
		DBTraceDataAdapter data = addData(snap, start, type, length);
		assertEquals(length, data.getLength());
		return data;
	}

	/**
	 * Create an instruction unit by disassembling existing bytes
	 * 
	 * @param snap the starting snap
	 * @param start the min address
	 * @param platform the platform for the language to disassemble
	 * @return the instruction unit
	 * @throws CodeUnitInsertionException if the instruction cannot be created
	 */
	public DBTraceInstruction addInstruction(long snap, Address start,
			TracePlatform platform) throws CodeUnitInsertionException {
		DBTraceCodeManager code = trace.getCodeManager();
		Language platformLanguage = platform.getLanguage();
		Disassembler dis =
			Disassembler.getDisassembler(platformLanguage, platformLanguage.getAddressFactory(),
				new ConsoleTaskMonitor(), msg -> Msg.info(this, "Listener: " + msg));
		RegisterValue defaultContextValue = trace.getRegisterContextManager()
				.getDefaultContext(platformLanguage)
				.getDefaultDisassemblyContext();

		MemBuffer memBuf = platform.getMappedMemBuffer(snap, platform.mapHostToGuest(start));
		InstructionBlock block = dis.pseudoDisassembleBlock(memBuf, defaultContextValue, 1);
		Instruction pseudoIns = block.iterator().next();
		return code.instructions()
				.create(Lifespan.nowOn(snap), start, platform, pseudoIns.getPrototype(), pseudoIns);
	}

	/**
	 * Create an instruction unit, first placing the given bytes, and disassembling
	 * 
	 * @param snap the starting snap
	 * @param start the min address
	 * @param platform the platform the the language to disassemble
	 * @param buf the bytes to place, which will become the unit's bytes
	 * @return the instruction unit
	 * @throws CodeUnitInsertionException if the instruction cannot be created
	 */
	public DBTraceInstruction addInstruction(long snap, Address start, TracePlatform platform,
			ByteBuffer buf) throws CodeUnitInsertionException {
		int length = buf.remaining();
		DBTraceMemoryManager memory = trace.getMemoryManager();
		memory.putBytes(snap, start, buf);
		DBTraceInstruction instruction = addInstruction(snap, start, platform);
		assertEquals(length, instruction.getLength());
		return instruction;
	}

	/**
	 * Ensure the given thread exists and retrieve it
	 * 
	 * @param name the thread's name
	 * @param creationSnap the snap where the thread must exist
	 * @return the thread
	 */
	public TraceThread getOrAddThread(String name, long creationSnap) {
		DBTraceThreadManager manager = trace.getThreadManager();
		Collection<? extends TraceThread> threads = manager.getThreadsByPath(name);
		if (threads != null && !threads.isEmpty()) {
			return threads.iterator().next();
		}
		try {
			return manager.createThread(name, creationSnap);
		}
		catch (DuplicateNameException e) {
			throw new AssertionError(e);
		}
	}

	/**
	 * Add a mnemonic memory reference
	 * 
	 * @param creationSnap the starting snap
	 * @param from the from address
	 * @param to the to address
	 * @return the reference
	 */
	public DBTraceReference addMemoryReference(long creationSnap, Address from, Address to) {
		return addMemoryReference(creationSnap, from, to, -1);
	}

	/**
	 * Add an operand memory reference
	 * 
	 * @param creationSnap the starting snap
	 * @param from the from address
	 * @param to the to address
	 * @param operandIndex the operand index, or -1 for mnemonic
	 * @return the reference
	 */
	public DBTraceReference addMemoryReference(long creationSnap, Address from, Address to,
			int operandIndex) {
		return trace.getReferenceManager()
				.addMemoryReference(Lifespan.nowOn(creationSnap), from, to,
					RefType.DATA, SourceType.DEFAULT, operandIndex);
	}

	/**
	 * Add a base-offset memory reference
	 * 
	 * @param creationSnap the starting snap
	 * @param from the from address
	 * @param to the to address
	 * @param toAddrIsBase true if {@code to} is the base address, implying offset must be added to
	 *            get the real to address.
	 * @param offset the offset
	 * @return the reference
	 */
	public DBTraceReference addOffsetReference(long creationSnap, Address from, Address to,
			boolean toAddrIsBase, long offset) {
		return trace.getReferenceManager()
				.addOffsetReference(Lifespan.nowOn(creationSnap), from, to, toAddrIsBase,
					offset, RefType.DATA, SourceType.DEFAULT, -1);
	}

	/**
	 * Add a shifted memory reference
	 * 
	 * <p>
	 * TODO: This uses opIndex -1, which doesn't make sense for a shifted reference. The "to"
	 * address is computed (I assume by the analyzer which places such reference) as the operand
	 * value shifted by the given shift amount. What is the opIndex for a data unit? Probably 0,
	 * since the "mnemonic" would be its type? Still, this suffices for testing the database.
	 * 
	 * @param creationSnap the starting snap
	 * @param from the from address
	 * @param to the to address
	 * @param shift the shift
	 * @return the reference
	 */
	public DBTraceReference addShiftedReference(long creationSnap, Address from, Address to,
			int shift) {
		return trace.getReferenceManager()
				.addShiftedReference(Lifespan.nowOn(creationSnap), from,
					to, shift, RefType.DATA, SourceType.DEFAULT, -1);
	}

	/**
	 * Add a register reference
	 * 
	 * <p>
	 * See
	 * {@link TraceReferenceManager#addRegisterReference(Lifespan, Address, Register, RefType, SourceType, int)}
	 * regarding potential confusion of the word "register" in this context.
	 * 
	 * @param creationSnap the starting snap
	 * @param from the from register
	 * @param to the to address
	 * @return the reference
	 */
	public DBTraceReference addRegisterReference(long creationSnap, Address from, String to) {
		return trace.getReferenceManager()
				.addRegisterReference(Lifespan.nowOn(creationSnap), from,
					language.getRegister(to), RefType.DATA, SourceType.DEFAULT, -1);
	}

	/**
	 * Add a stack reference
	 * 
	 * <p>
	 * See
	 * {@link TraceReferenceManager#addStackReference(Lifespan, Address, int, RefType, SourceType, int)}
	 * regarding potential confusion of the word "stack" in this context.
	 * 
	 * @param creationSnap the starting snap
	 * @param from the from address
	 * @param to the to stack offset
	 * @return the reference
	 */
	public DBTraceReference addStackReference(long creationSnap, Address from, int to) {
		return trace.getReferenceManager()
				.addStackReference(Lifespan.nowOn(creationSnap), from, to,
					RefType.DATA, SourceType.DEFAULT, -1);
	}

	/**
	 * Save the trace to a temporary .gzf file
	 * 
	 * @return the new file
	 * @throws IOException if the trace could not be saved
	 * @throws CancelledException never, since the monitor cannot be cancelled
	 */
	public File save() throws IOException, CancelledException {
		Path tmp = Files.createTempFile("test", ".db");
		Files.delete(tmp); // saveAs must create the file
		trace.getDBHandle().saveAs(tmp.toFile(), false, new ConsoleTaskMonitor());
		return tmp.toFile();
	}

	/**
	 * Get the language with the given ID, as in {@link LanguageID}
	 * 
	 * @param id the ID
	 * @return the language
	 * @throws LanguageNotFoundException if the language does not exist
	 */
	public Language getLanguage(String id) throws LanguageNotFoundException {
		return languageService.getLanguage(new LanguageID(id));
	}

	/**
	 * Get the compiler spec with the given language and compiler IDs
	 * 
	 * @param langID the language ID as in {@link LanguageID}
	 * @param compID the compiler ID as in {@link CompilerSpecID}
	 * @return the compiler spec
	 * @throws CompilerSpecNotFoundException if the compiler spec does not exist
	 * @throws LanguageNotFoundException if the language does not exist
	 */
	public CompilerSpec getCompiler(String langID, String compID)
			throws CompilerSpecNotFoundException, LanguageNotFoundException {
		return getLanguage(langID).getCompilerSpecByID(new CompilerSpecID(compID));
	}

	@Override
	public void close() {
		if (trace.getConsumerList().contains(this)) {
			trace.release(this);
		}
	}
}
