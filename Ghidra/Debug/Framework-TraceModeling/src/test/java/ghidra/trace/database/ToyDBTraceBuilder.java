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

import java.awt.Color;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.Objects;

import com.google.common.collect.Range;

import db.DBHandle;
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
import ghidra.trace.database.language.DBTraceGuestLanguage;
import ghidra.trace.database.listing.*;
import ghidra.trace.database.memory.DBTraceMemoryManager;
import ghidra.trace.database.symbol.DBTraceReference;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.database.thread.DBTraceThreadManager;
import ghidra.trace.model.ImmutableTraceAddressSnapRange;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.language.TraceGuestLanguage;
import ghidra.util.Msg;
import ghidra.util.database.DBOpenMode;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.exception.*;
import ghidra.util.task.ConsoleTaskMonitor;

public class ToyDBTraceBuilder implements AutoCloseable {
	public final Language language;
	public final DBTrace trace;
	public final LanguageService languageService = DefaultLanguageService.getLanguageService();

	public ToyDBTraceBuilder(File file)
			throws CancelledException, VersionException, LanguageNotFoundException, IOException {
		DBHandle handle = new DBHandle(file);
		this.trace = new DBTrace(handle, DBOpenMode.UPDATE, new ConsoleTaskMonitor(), this);
		this.language = trace.getBaseLanguage();
	}

	// TODO: A constructor for specifying compiler, too
	public ToyDBTraceBuilder(String name, String langID) throws IOException {
		this.language = languageService.getLanguage(new LanguageID(langID));
		this.trace = new DBTrace(name, language.getDefaultCompilerSpec(), this);
	}

	public Address addr(AddressSpace space, long offset) {
		return space.getAddress(offset);
	}

	public Address addr(Language lang, long offset) {
		return addr(lang.getDefaultSpace(), offset);
	}

	public Address addr(long offset) {
		return addr(language, offset);
	}

	public Address addr(TraceGuestLanguage lang, long offset) {
		return lang.getLanguage().getDefaultSpace().getAddress(offset);
	}

	public Address data(Language lang, long offset) {
		return addr(lang.getDefaultDataSpace(), offset);
	}

	public Address data(long offset) {
		return data(language, offset);
	}

	public Address data(TraceGuestLanguage lang, long offset) {
		return data(lang.getLanguage(), offset);
	}

	public AddressRange range(Address start, Address end) {
		return new AddressRangeImpl(start, end);
	}

	public AddressRange range(AddressSpace space, long start, long end) {
		return range(addr(space, start), addr(space, end));
	}

	public AddressRange range(Language lang, long start, long end) {
		return range(lang.getDefaultSpace(), start, end);
	}

	public AddressRange range(long start, long end) {
		return range(language, start, end);
	}

	public AddressRange range(long singleton) {
		return range(singleton, singleton);
	}

	public TraceAddressSnapRange srange(long snap, long start, long end) {
		return new ImmutableTraceAddressSnapRange(addr(start), addr(end), snap, snap);
	}

	public AddressRange drng(Language lang, long start, long end) {
		return range(language.getDefaultDataSpace(), start, end);
	}

	public AddressRange drng(long start, long end) {
		return drng(language, start, end);
	}

	public AddressRange range(TraceGuestLanguage lang, long start, long end) {
		return range(lang.getLanguage(), start, end);
	}

	public AddressRange drng(TraceGuestLanguage lang, long start, long end) {
		return drng(lang.getLanguage(), start, end);
	}

	public AddressSetView set(AddressRange... ranges) {
		AddressSet result = new AddressSet();
		for (AddressRange rng : ranges) {
			result.add(rng);
		}
		return result;
	}

	public byte[] arr(int... e) {
		byte[] result = new byte[e.length];
		for (int i = 0; i < e.length; i++) {
			result[i] = (byte) e[i];
		}
		return result;
	}

	public ByteBuffer buf(int... e) {
		return ByteBuffer.wrap(arr(e));
	}

	public ByteBuffer buf(String str) {
		CharsetEncoder ce = Charset.forName("UTF-8").newEncoder();
		ByteBuffer result =
			ByteBuffer.allocate(Math.round(ce.maxBytesPerChar() * str.length()) + 1);
		ce.encode(CharBuffer.wrap(str), result, true);
		result.put((byte) 0);
		return result.flip();
	}

	public UndoableTransaction startTransaction() {
		return UndoableTransaction.start(trace, "Testing", true);
	}

	public DBTraceBookmarkType getOrAddBookmarkType(String name) {
		DBTraceBookmarkManager manager = trace.getBookmarkManager();
		return manager.defineBookmarkType(name, null, Color.red, 1);
	}

	public DBTraceBookmark addBookmark(long snap, long addr, String typeName, String category,
			String comment) {
		DBTraceBookmarkType type = getOrAddBookmarkType(typeName);
		DBTraceBookmarkManager manager = trace.getBookmarkManager();
		DBTraceBookmark bm =
			manager.addBookmark(Range.atLeast(snap), addr(addr), type, category, comment);
		assertNull(bm.getThread());
		assertEquals(snap, bm.getLifespan().lowerEndpoint().longValue());
		assertEquals(addr(addr), bm.getAddress());
		assertEquals(typeName, bm.getTypeString());
		assertEquals(category, bm.getCategory());
		assertEquals(comment, bm.getComment());
		return bm;
	}

	public DBTraceBookmark addRegisterBookmark(long snap, String threadName, String registerName,
			String typeName, String category, String comment) throws DuplicateNameException {
		Register register = language.getRegister(registerName);
		assertNotNull(register);
		DBTraceThread thread = getOrAddThread(threadName, snap);
		DBTraceBookmarkType type = getOrAddBookmarkType(typeName);
		DBTraceBookmarkManager manager = trace.getBookmarkManager();
		DBTraceBookmarkRegisterSpace space = manager.getBookmarkRegisterSpace(thread, true);
		DBTraceBookmark bm = (DBTraceBookmark) space.addBookmark(Range.atLeast(snap), register,
			type, category, comment);
		assertSame(thread, bm.getThread());
		assertEquals(snap, bm.getLifespan().lowerEndpoint().longValue());
		assertEquals(register.getAddress(), bm.getAddress());
		assertEquals(typeName, bm.getTypeString());
		assertEquals(category, bm.getCategory());
		return bm;
	}

	public DBTraceDataAdapter addData(long snap, Address start, DataType type, int length)
			throws CodeUnitInsertionException {
		DBTraceCodeManager code = trace.getCodeManager();
		return code.definedData().create(Range.atLeast(snap), start, type, length);
	}

	public DBTraceDataAdapter addData(long snap, Address start, DataType type, ByteBuffer buf)
			throws CodeUnitInsertionException {
		int length = buf.remaining();
		DBTraceMemoryManager memory = trace.getMemoryManager();
		memory.putBytes(snap, start, buf);
		DBTraceDataAdapter data = addData(snap, start, type, length);
		assertEquals(length, data.getLength());
		return data;
	}

	public DBTraceInstruction addInstruction(long snap, Address start,
			@SuppressWarnings("hiding") Language language) throws CodeUnitInsertionException {
		DBTraceMemoryManager memory = trace.getMemoryManager();
		DBTraceCodeManager code = trace.getCodeManager();
		Disassembler dis = Disassembler.getDisassembler(language, language.getAddressFactory(),
			new ConsoleTaskMonitor(), msg -> Msg.info(this, "Listener: " + msg));
		RegisterValue defaultContextValue = trace.getRegisterContextManager()
				.getDefaultContext(language)
				.getDefaultDisassemblyContext();

		MemBuffer memBuf;
		if (language == null || Objects.equals(this.language, language)) {
			memBuf = memory.getBufferAt(snap, start);
		}
		else {
			DBTraceGuestLanguage guest = trace.getLanguageManager().getGuestLanguage(language);
			memBuf = guest.getMappedMemBuffer(snap, guest.mapHostToGuest(start));
		}
		InstructionBlock block = dis.pseudoDisassembleBlock(memBuf, defaultContextValue, 1);
		Instruction pseudoIns = block.iterator().next();
		return code.instructions()
				.create(Range.atLeast(snap), start, pseudoIns.getPrototype(),
					pseudoIns);
	}

	public DBTraceInstruction addInstruction(long snap, Address start,
			@SuppressWarnings("hiding") Language language, ByteBuffer buf)
			throws CodeUnitInsertionException {
		int length = buf.remaining();
		DBTraceMemoryManager memory = trace.getMemoryManager();
		memory.putBytes(snap, start, buf);
		DBTraceInstruction instruction = addInstruction(snap, start, language);
		assertEquals(length, instruction.getLength());
		return instruction;
	}

	public DBTraceThread getOrAddThread(String name, long creationSnap)
			throws DuplicateNameException {
		DBTraceThreadManager manager = trace.getThreadManager();
		Collection<? extends DBTraceThread> threads = manager.getThreadsByPath(name);
		if (threads != null && !threads.isEmpty()) {
			return threads.iterator().next();
		}
		return (DBTraceThread) manager.createThread(name, creationSnap);
	}

	public DBTraceReference addMemoryReference(long creationSnap, Address from, Address to) {
		return addMemoryReference(creationSnap, from, to, -1);
	}

	public DBTraceReference addMemoryReference(long creationSnap, Address from, Address to,
			int operandIndex) {
		return trace.getReferenceManager()
				.addMemoryReference(Range.atLeast(creationSnap), from, to,
					RefType.DATA, SourceType.DEFAULT, operandIndex);
	}

	public DBTraceReference addOffsetReference(long creationSnap, Address from, Address to,
			long offset) {
		return trace.getReferenceManager()
				.addOffsetReference(Range.atLeast(creationSnap), from, to,
					offset, RefType.DATA, SourceType.DEFAULT, -1);
	}

	public DBTraceReference addShiftedReference(long creationSnap, Address from, Address to,
			int shift) {
		return trace.getReferenceManager()
				.addShiftedReference(Range.atLeast(creationSnap), from,
					to, shift, RefType.DATA, SourceType.DEFAULT, -1);
	}

	public DBTraceReference addRegisterReference(long creationSnap, Address from, String to) {
		return trace.getReferenceManager()
				.addRegisterReference(Range.atLeast(creationSnap), from,
					language.getRegister(to), RefType.DATA, SourceType.DEFAULT, -1);
	}

	public DBTraceReference addStackReference(long creationSnap, Address from, int to) {
		return trace.getReferenceManager()
				.addStackReference(Range.atLeast(creationSnap), from, to,
					RefType.DATA, SourceType.DEFAULT, -1);
	}

	public File save() throws IOException, CancelledException {
		Path tmp = Files.createTempFile("test", ".db");
		Files.delete(tmp); // saveAs must create the file
		trace.getDBHandle().saveAs(tmp.toFile(), false, new ConsoleTaskMonitor());
		return tmp.toFile();
	}

	@Override
	public void close() {
		trace.release(this);
	}

	public Language getLanguage(String id) throws LanguageNotFoundException {
		return languageService.getLanguage(new LanguageID(id));
	}
}
