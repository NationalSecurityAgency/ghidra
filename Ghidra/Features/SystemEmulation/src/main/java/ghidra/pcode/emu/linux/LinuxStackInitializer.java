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
package ghidra.pcode.emu.linux;

import java.nio.*;
import java.nio.charset.Charset;
import java.nio.charset.CoderResult;
import java.security.SecureRandom;
import java.util.*;

import ghidra.pcode.emu.elf.ElfHeaderReader;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;

/**
 * TODO: Think about abstracting this across target platforms
 * 
 * This is not complete by any stretch of the imagination.
 */
public class LinuxStackInitializer {

	enum AuxvType {
		AT_NULL(0),
		AT_IGNORE(1),
		AT_EXECFD(2),
		AT_PHDR(3),
		AT_PHENT(4),
		AT_PHNUM(5),
		AT_PAGESZ(6),
		AT_BASE(7),
		AT_FLAGS(8),
		AT_ENTRY(9),
		AT_NOTELF(10),
		AT_UID(11),
		AT_EUID(12),
		AT_GID(13),
		AT_EGID(14),
		AT_CLKTCK(17),
		AT_PLATFORM(15),
		AT_HWCAP(16),
		AT_FPUCW(18),
		AT_DCACHEBSIZE(19),
		AT_ICACHEBSIZE(20),
		AT_UCACHEBSIZE(21),
		AT_IGNOREPPC(22),
		AT_SECURE(23),
		AT_BASE_PLATFORM(24),
		AT_RANDOM(25),
		AT_HWCAP2(26),
		AT_RSEQ_FEATURE_SIZE(27),
		AT_RSEQ_ALIGN(28),
		AT_EXECFN(31),
		AT_SYSINFO(32),
		AT_SYSINFO_EHDR(33),
		AT_L1I_CACHESHAPE(34),
		AT_L1D_CACHESHAPE(35),
		AT_L2_CACHESHAPE(36),
		AT_L3_CACHESHAPE(37),
		AT_L1I_CACHESIZE(40),
		AT_L1I_CACHEGEOMETRY(41),
		AT_L1D_CACHESIZE(42),
		AT_L1D_CACHEGEOMETRY(43),
		AT_L2_CACHESIZE(44),
		AT_L2_CACHEGEOMETRY(45),
		AT_L3_CACHESIZE(46),
		AT_L3_CACHEGEOMETRY(47),
		AT_MINSIGSTKSZ(51),
		;

		public final long num;

		private AuxvType(long num) {
			this.num = num;
		}
	}

	interface AuxvVal {
		long placeValue(ByteBuffer data, long dataOffset);

		static AuxvVal val(long value) {
			return new LongAuxvVal(value);
		}

		static AuxvVal addr(Address address) {
			return new LongAuxvVal(address.getOffset());
		}

		static AuxvVal bytes(byte[] bytes) {
			return new BytesAuxvVal(bytes);
		}
	}

	record LongAuxvVal(long value) implements AuxvVal {
		@Override
		public long placeValue(ByteBuffer data, long dataOffset) {
			return value;
		}
	}

	record BytesAuxvVal(byte[] value) implements AuxvVal {
		@Override
		public long placeValue(ByteBuffer data, long dataOffset) {
			long result = dataOffset + data.position();
			data.put(value);
			return result;
		}
	}

	private final List<String> argv = new ArrayList<>();
	private final Map<String, String> env = new LinkedHashMap<>();
	private final Map<AuxvType, AuxvVal> auxv = new LinkedHashMap<>();

	private final int bits;
	private final ByteOrder order;
	private final Charset charset;
	private final SecureRandom random;

	public LinuxStackInitializer(Language language, Charset charset, SecureRandom random) {
		this.bits = language.getLanguageDescription().getSize();
		this.order = language.isBigEndian() ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
		this.charset = charset;
		this.random = random;
	}

	public void arg(String arg) {
		argv.add(arg);
	}

	public void env(String key, String value) {
		env.put(key, value);
	}

	public void auxv(AuxvType type, AuxvVal value) {
		auxv.put(type, value);
	}

	/**
	 * Populate the auxiliary vector with entries taken from the given program
	 * 
	 * @param program the program
	 * @param dynBase the dynamic base, or null to use the program's static image base
	 */
	public void program(Program program, Address dynBase) { // not ld-linux, but the program
		// NOTE: Much of this depends on behavior of Ghidra's ELF loader/importer
		ElfHeaderReader elfReader = new ElfHeaderReader(program);
		if (dynBase == null) {
			dynBase = elfReader.getLoadedImageBase();
		}

		// Don't use reader's header address. That's wrt./ static image base.
		long elfPhoff = elfReader.getProgramHeadersOffset();
		auxv(AuxvType.AT_PHDR, AuxvVal.addr(dynBase.add(elfPhoff)));

		long elfPhnum = elfReader.getProgramHeadersCount();
		auxv(AuxvType.AT_PHNUM, AuxvVal.val(elfPhnum));

		long elfPhentsize = elfReader.getProgramHeaderEntrySize();
		auxv(AuxvType.AT_PHENT, AuxvVal.val(elfPhentsize));

		auxv(AuxvType.AT_PAGESZ, AuxvVal.val(4096));

		byte[] bytes = new byte[16];
		random.nextBytes(bytes);
		auxv(AuxvType.AT_RANDOM, AuxvVal.bytes(bytes));

		Address elfEntry = elfReader.getNominalEntry();
		Address dynEntry = dynBase.add(elfEntry.subtract(elfReader.getNominalImageBase()));
		auxv(AuxvType.AT_ENTRY, AuxvVal.addr(dynEntry));
	}

	public void encode(long offset, ByteBuffer buf) {
		buf.order(order);
		int auxv_t_size = bits / Byte.SIZE * 2;

		buf.putLong(argv.size()); // argc

		long entriesEnd = offset +
			Long.BYTES + // argc
			argv.size() * Long.BYTES + // ptr each argv
			Long.BYTES + // null terminator
			env.size() * Long.BYTES + // ptr each env
			Long.BYTES + // null terminator
			auxv.size() * auxv_t_size + // each auxv entry
			auxv_t_size + // null entry terminator
			0; // 
		long dataOffset = (entriesEnd + 15) / 16 * 16;

		ByteBuffer data = ByteBuffer.allocate(buf.capacity());
		for (String a : argv) {
			buf.putLong(dataOffset + data.position());
			CoderResult result = charset.newEncoder().encode(CharBuffer.wrap(a), data, true);
			if (result.isError() || result.isOverflow()) {
				throw new AssertionError("Could not encode arguments: " + result);
			}
			data.put((byte) 0);
		}
		buf.putLong(0); // NULL

		for (Map.Entry<String, String> e : env.entrySet()) {
			String s = "%s=%s".formatted(e.getKey(), e.getValue());
			buf.putLong(dataOffset + data.position());
			CoderResult result = charset.newEncoder().encode(CharBuffer.wrap(s), data, true);
			if (result.isError() || result.isOverflow()) {
				throw new AssertionError("Could not encode environment: " + result);
			}
			data.put((byte) 0);
		}
		buf.putLong(0); // NULL

		for (Map.Entry<AuxvType, AuxvVal> av : auxv.entrySet()) {
			buf.putLong(av.getKey().num);
			buf.putLong(av.getValue().placeValue(data, dataOffset));
		}
		buf.putLong(0); // NULL type
		buf.putLong(0); // NULL value

		int padding = (int) (dataOffset - entriesEnd);
		buf.position(buf.position() + padding);
		data.flip();
		buf.put(data);
	}
}
