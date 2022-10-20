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
package ghidra.trace.model.time.schedule;

import java.math.BigInteger;
import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Stream;

import javax.help.UnsupportedOperationException;

import generic.ULongSpan;
import generic.ULongSpan.*;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.generic.util.datastruct.SemisparseByteArray;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.*;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class PatchStep implements Step {
	protected final long threadKey;
	protected String sleigh;
	protected int hashCode;

	/**
	 * Generate a single line of Sleigh
	 * 
	 * <p>
	 * Note that when length is greater than 8, this will generate constants which are too large for
	 * the Java implementation of Sleigh. Use {@link #generateSleigh(Language, Address, byte[])}
	 * instead to write the variable in chunks.
	 * 
	 * @param language the target language
	 * @param address the (start) address of the variable
	 * @param data the bytes to write to the variable
	 * @param length the length of the variable
	 * @return the Sleigh code
	 */
	public static String generateSleighLine(Language language, Address address, byte[] data,
			int length) {
		BigInteger value = Utils.bytesToBigInteger(data, length, language.isBigEndian(), false);
		if (address.isMemoryAddress()) {
			AddressSpace space = address.getAddressSpace();
			if (language.getDefaultSpace() == space) {
				return String.format("*:%d 0x%s:%d=0x%s",
					length,
					address.getOffsetAsBigInteger().toString(16), space.getPointerSize(),
					value.toString(16));
			}
			return String.format("*[%s]:%d 0x%s:%d=0x%s",
				space.getName(), length,
				address.getOffsetAsBigInteger().toString(16), space.getPointerSize(),
				value.toString(16));
		}
		Register register = language.getRegister(address, length);
		if (register == null) {
			throw new AssertionError("Can only modify memory or register");
		}
		return String.format("%s=0x%s", register, value.toString(16));
	}

	/**
	 * Generate a single line of Sleigh
	 * 
	 * @see #generateSleighLine(Language, Address, byte[], int)
	 */
	public static String generateSleighLine(Language language, Address address, byte[] data) {
		return generateSleighLine(language, address, data, data.length);
	}

	/**
	 * Generate multiple lines of Sleigh, all to set a single variable
	 * 
	 * @param language the target language
	 * @param address the (start) address of the variable
	 * @param data the bytes to write to the variable
	 * @return the lines of Sleigh code
	 */
	public static List<String> generateSleigh(Language language, Address address, byte[] data) {
		List<String> result = new ArrayList<>();
		generateSleigh(result, language, address, data);
		return result;
	}

	protected static void generateSleigh(List<String> result, Language language, Address address,
			byte[] data) {
		SemisparseByteArray array = new SemisparseByteArray(); // TODO: Seems heavy-handed
		array.putData(address.getOffset(), data);
		generateSleigh(result, language, address.getAddressSpace(), array);
	}

	protected static List<String> generateSleigh(Language language,
			Map<AddressSpace, SemisparseByteArray> patches) {
		List<String> result = new ArrayList<>();
		for (Entry<AddressSpace, SemisparseByteArray> entry : patches.entrySet()) {
			generateSleigh(result, language, entry.getKey(), entry.getValue());
		}
		return result;
	}

	protected static void generateSleigh(List<String> result, Language language, AddressSpace space,
			SemisparseByteArray array) {
		if (space.isRegisterSpace()) {
			generateRegisterSleigh(result, language, space, array);
		}
		else {
			generateMemorySleigh(result, language, space, array);
		}
	}

	protected static void generateMemorySleigh(List<String> result, Language language,
			AddressSpace space, SemisparseByteArray array) {
		byte[] data = new byte[8];
		for (ULongSpan span : array.getInitialized(0, -1).spans()) {
			Address start = space.getAddress(span.min());
			Address end = space.getAddress(span.max());
			for (AddressRange chunk : new AddressRangeChunker(start, end, data.length)) {
				Address min = chunk.getMinAddress();
				int length = (int) chunk.getLength();
				array.getData(min.getOffset(), data, 0, length);
				result.add(generateSleighLine(language, min, data, length));
			}
		}
	}

	protected static ULongSpan spanOfRegister(Register r) {
		return ULongSpan.extent(r.getAddress().getOffset(), r.getNumBytes());
	}

	protected static boolean isContained(Register r, ULongSpanSet remains) {
		return remains.encloses(spanOfRegister(r));
	}

	protected static void generateRegisterSleigh(List<String> result, Language language,
			AddressSpace space, SemisparseByteArray array) {
		byte[] data = new byte[8];
		MutableULongSpanSet remains = new DefaultULongSpanSet();
		remains.addAll(array.getInitialized(0, -1));
		while (!remains.isEmpty()) {
			ULongSpan bound = remains.bound();
			Address min = space.getAddress(bound.min());
			Register register = Stream.of(language.getRegisters(min))
					.filter(r -> r.getAddress().equals(min))
					.filter(r -> r.getNumBytes() <= data.length)
					.filter(r -> isContained(r, remains))
					.sorted(Comparator.comparing(r -> -r.getNumBytes()))
					.findFirst()
					.orElse(null);
			if (register == null) {
				throw new IllegalArgumentException("Could not find a register for " + min);
			}
			int length = register.getNumBytes();
			array.getData(min.getOffset(), data, 0, length);
			BigInteger value = Utils.bytesToBigInteger(data, length, language.isBigEndian(), false);
			result.add(String.format("%s=0x%s", register, value.toString(16)));
			remains.remove(spanOfRegister(register));
		}
	}

	public static PatchStep parse(long threadKey, String stepSpec) {
		// TODO: Can I parse and validate the sleigh here?
		if (!stepSpec.startsWith("{") || !stepSpec.endsWith("}")) {
			throw new IllegalArgumentException("Cannot parse step: '" + stepSpec + "'");
		}
		return new PatchStep(threadKey, stepSpec.substring(1, stepSpec.length() - 1));
	}

	public PatchStep(long threadKey, String sleigh) {
		this.threadKey = threadKey;
		this.sleigh = Objects.requireNonNull(sleigh);
		this.hashCode = Objects.hash(threadKey, sleigh); // TODO: May become mutable
	}

	private void setSleigh(String sleigh) {
		this.sleigh = sleigh;
		this.hashCode = Objects.hash(threadKey, sleigh);
	}

	@Override
	public int hashCode() {
		return hashCode;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof PatchStep)) {
			return false;
		}
		PatchStep that = (PatchStep) obj;
		if (this.threadKey != that.threadKey) {
			return false;
		}
		if (!this.sleigh.equals(that.sleigh)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		if (threadKey == -1) {
			return "{" + sleigh + "}";
		}
		return String.format("t%d-{%s}", threadKey, sleigh);
	}

	@Override
	public StepType getType() {
		return StepType.PATCH;
	}

	@Override
	public boolean isNop() {
		// TODO: If parsing beforehand, base on number of ops
		return sleigh.length() == 0;
	}

	@Override
	public long getThreadKey() {
		return threadKey;
	}

	@Override
	public long getTickCount() {
		return 0; // Philosophically correct
	}

	@Override
	public long getPatchCount() {
		return 1;
	}

	@Override
	public boolean isCompatible(Step step) {
		// TODO: Can we combine ops?
		return false; // For now, never combine sleigh steps
	}

	@Override
	public void addTo(Step step) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Step subtract(Step step) {
		if (this.equals(step)) {
			return Step.nop();
		}
		throw new UnsupportedOperationException();
	}

	@Override
	public Step clone() {
		return new PatchStep(threadKey, sleigh);
	}

	@Override
	public long rewind(long count) {
		return count - 1;
	}

	@Override
	public CompareResult compareStep(Step step) {
		CompareResult result;

		result = compareStepType(step);
		if (result != CompareResult.EQUALS) {
			return result;
		}

		PatchStep that = (PatchStep) step;
		result = CompareResult.unrelated(Long.compare(this.threadKey, that.threadKey));
		if (result != CompareResult.EQUALS) {
			return result;
		}

		// TODO: Compare ops, if/when we pre-compile
		result = CompareResult.unrelated(this.sleigh.compareTo(that.sleigh));
		if (result != CompareResult.EQUALS) {
			return result;
		}

		return CompareResult.EQUALS;
	}

	@Override
	public <T> void execute(PcodeThread<T> emuThread, Stepper stepper, TaskMonitor monitor)
			throws CancelledException {
		PcodeProgram prog = emuThread.getMachine().compileSleigh("schedule", sleigh + ";");
		emuThread.getExecutor().execute(prog, emuThread.getUseropLibrary());
	}

	@Override
	public long coalescePatches(Language language, List<Step> steps) {
		long threadKey = -1;
		int toRemove = 0;
		Map<AddressSpace, SemisparseByteArray> patches = new TreeMap<>();
		for (int i = steps.size() - 1; i >= 0; i--) {
			Step step = steps.get(i);
			long stk = step.getThreadKey();
			if (threadKey == -1) {
				threadKey = stk;
			}
			else if (stk != -1 && stk != threadKey) {
				break;
			}
			if (!(step instanceof PatchStep)) {
				break;
			}
			PatchStep ps = (PatchStep) step;
			Map<AddressSpace, SemisparseByteArray> subs = ps.getPatches(language);
			if (subs == null) {
				break;
			}
			mergePatches(subs, patches);
			patches = subs;
			toRemove++;
		}
		List<String> sleighPatches = generateSleigh(language, patches);
		assert sleighPatches.size() <= toRemove;
		for (String sleighPatch : sleighPatches) {
			PatchStep ps = (PatchStep) steps.get(steps.size() - toRemove);
			ps.setSleigh(sleighPatch);
			toRemove--;
		}
		return toRemove;
	}

	protected void mergePatches(Map<AddressSpace, SemisparseByteArray> into,
			Map<AddressSpace, SemisparseByteArray> from) {
		for (Entry<AddressSpace, SemisparseByteArray> entry : from.entrySet()) {
			if (!into.containsKey(entry.getKey())) {
				into.put(entry.getKey(), entry.getValue());
			}
			else {
				into.get(entry.getKey()).putAll(entry.getValue());
			}
		}
	}

	protected Map<AddressSpace, SemisparseByteArray> getPatches(Language language) {
		PcodeProgram prog = SleighProgramCompiler.compileProgram((SleighLanguage) language,
			"schedule", sleigh + ";", PcodeUseropLibrary.nil());
		// SemisparseArray is a bit overkill, no?
		Map<AddressSpace, SemisparseByteArray> result = new TreeMap<>();
		for (PcodeOp op : prog.getCode()) {
			// Only accept patches in form [mem/reg] = [constant]
			switch (op.getOpcode()) {
				case PcodeOp.COPY:
					if (!getPatchCopyOp(language, result, op)) {
						return null;
					}
					break;
				case PcodeOp.STORE:
					if (!getPatchStoreOp(language, result, op)) {
						return null;
					}
					break;
				default:
					return null;
			}
		}
		return result;
	}

	protected boolean getPatchCopyOp(Language language,
			Map<AddressSpace, SemisparseByteArray> result, PcodeOp op) {
		Varnode output = op.getOutput();
		if (!output.isAddress() && !output.isRegister()) {
			return false;
		}
		Varnode input = op.getInput(0);
		if (!input.isConstant()) {
			return false;
		}
		Address address = output.getAddress();
		SemisparseByteArray array = result.computeIfAbsent(address.getAddressSpace(),
			as -> new SemisparseByteArray());
		array.putData(address.getOffset(),
			Utils.longToBytes(input.getOffset(), input.getSize(),
				language.isBigEndian()));
		return true;
	}

	protected boolean getPatchStoreOp(Language language,
			Map<AddressSpace, SemisparseByteArray> result,
			PcodeOp op) {
		Varnode vnSpace = op.getInput(0);
		if (!vnSpace.isConstant()) {
			return false;
		}
		AddressSpace space =
			language.getAddressFactory().getAddressSpace((int) vnSpace.getOffset());
		Varnode vnOffset = op.getInput(1);
		if (!vnOffset.isConstant()) {
			return false;
		}
		Varnode vnValue = op.getInput(2);
		if (!vnValue.isConstant()) {
			return false;
		}
		SemisparseByteArray array = result.computeIfAbsent(space, as -> new SemisparseByteArray());
		array.putData(vnOffset.getOffset(), Utils.longToBytes(vnValue.getOffset(),
			vnValue.getSize(), language.isBigEndian()));
		return true;
	}

}
