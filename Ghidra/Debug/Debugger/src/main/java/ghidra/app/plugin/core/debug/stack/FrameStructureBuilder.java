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
package ghidra.app.plugin.core.debug.stack;

import java.util.*;
import java.util.Map.Entry;

import generic.ULongSpan;
import generic.ULongSpan.DefaultULongSpanSet;
import generic.ULongSpan.MutableULongSpanSet;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.trace.model.data.TraceBasedDataTypeManager;
import ghidra.util.Msg;

/**
 * The implementation of {@link AnalysisUnwoundFrame#generateStructure(int)}
 */
class FrameStructureBuilder {
	public static final String RETURN_ADDRESS_FIELD_NAME = "return_address";
	public static final String SAVED_REGISTER_FIELD_PREFIX = "saved_";

	private record FrameField(Address address, String name, DataType type, int length,
			int scopeStart) {
		AddressRange range() {
			return new AddressRangeImpl(address, address.add(length - 1));
		}

		boolean overlaps(FrameStructureBuilder.FrameField that) {
			return range().intersects(that.range());
		}
	}

	private final AddressSpace codeSpace;
	private final Register pc;
	private final Address min;
	private Address max; // Exclusive
	private final long functionOffset;
	private final NavigableMap<Address, FrameStructureBuilder.FrameField> fields = new TreeMap<>();

	/**
	 * Builder for a structure based on unwind info and function stack variables
	 * 
	 * @param language the language defining the program counter register and code address space
	 * @param pcVal the value of the program counter, used to determine variable scope
	 * @param info the unwind information
	 * @param prevParamSize the number of bytes past the stack pointer at entry used by the previous
	 *            frame, typically for its parameters
	 */
	FrameStructureBuilder(Language language, Address pcVal, UnwindInfo info, int prevParamSize) {
		this.codeSpace = language.getDefaultSpace();
		this.pc = language.getProgramCounter();
		this.min = info.function()
				.getProgram()
				.getAddressFactory()
				.getStackSpace()
				.getAddress(info.depth() + prevParamSize);
		this.max = min;
		this.functionOffset = pcVal.subtract(info.function().getEntryPoint());
		processSaved(info.saved());
		if (info.ofReturn() != null) {
			processOfReturn(info.ofReturn());
		}
		processFunction(info.function());
	}

	/**
	 * Remove overlapping fields
	 * 
	 * <p>
	 * Entries with later {@link FrameField#scopeStart()} are preferred. No fields are generated for
	 * variables whose scope starts come after the current instruction offset, so that should ensure
	 * the most relevant variables are selected. Variables are always preferred over saved
	 * registers. Ideally, the return address should not conflict, but if it does, the return
	 * address is preferred, esp., since it is necessary to unwind the next frame.
	 * 
	 * @return the list of non-overlapping fields
	 */
	protected List<FrameStructureBuilder.FrameField> resolveOverlaps() {
		List<FrameStructureBuilder.FrameField> result = new ArrayList<>(fields.size());
		Entry<Address, FrameStructureBuilder.FrameField> ent1 = fields.pollFirstEntry();
		next1: while (ent1 != null) {
			FrameStructureBuilder.FrameField field1 = ent1.getValue();
			next2: while (true) {
				Entry<Address, FrameStructureBuilder.FrameField> ent2 = fields.pollFirstEntry();
				if (ent2 == null) {
					result.add(field1);
					return result;
				}
				FrameStructureBuilder.FrameField field2 = ent2.getValue();
				if (!field1.overlaps(field2)) {
					result.add(field1);
					ent1 = ent2;
					continue next1;
				}
				if (field1.scopeStart() > field2.scopeStart()) {
					// Drop field2, but we still need to check if field1 overlaps the next
					continue next2;
				}
				else if (field1.scopeStart() < field2.scopeStart()) {
					// Drop field1
					ent1 = ent2;
					continue next1;
				}
				else {
					Msg.warn(this,
						"Two overlapping variables with equal first use offsets....");
					// Prefer field1, I guess
					continue next2;
				}
			}
		}
		return result;
	}

	/**
	 * Build the resulting structure
	 * 
	 * @param path the category path for the new structure
	 * @param name the name of the new structure
	 * @param dtm the data type manager for the structure
	 * @return the new structure
	 */
	public Structure build(CategoryPath path, String name, TraceBasedDataTypeManager dtm) {
		List<FrameStructureBuilder.FrameField> resolved = resolveOverlaps();
		if (resolved.isEmpty()) {
			return null;
		}
		int length = (int) max.subtract(min);
		if (length == 0) {
			return null;
		}
		Structure structure = new StructureDataType(path, name, length, dtm);
		MutableULongSpanSet undefined = new DefaultULongSpanSet();
		undefined.add(ULongSpan.extent(0, structure.getLength()));
		for (FrameStructureBuilder.FrameField field : resolved) {
			int offset = (int) field.address().subtract(min);
			if (offset < 0) {
				/**
				 * No function should reach beyond the current stack pointer, especially near a
				 * call, since that space is presumed to belong to the callee. When we see variables
				 * beyond the current depth, it's likely they're just not in scope. For example, a
				 * local variable may be allocated on the stack when entering a block, so Ghidra
				 * will show that variable in the frame. However, we may encounter a program counter
				 * during unwinding that has not entered that block, or if it did, has already
				 * exited and deallocated the local. We must omit such variables. NOTE: For some
				 * variables, notably those that re-use storage, we do note the start of it scope,
				 * but not the end.
				 * 
				 * The min also accounts for the parameters in the previous frame. We'll observe
				 * writes to those, but we shouldn't see reads. Depending on changes to the unwind
				 * static analysis, passed parameters could get mistaken for saved registers.
				 * Nevertheless, we should prefer to assign overlapped portions of frames to the
				 * frame that uses them for parameters rather than scratch space. If diagnostics are
				 * desired, we may need to distinguish min from the SP vs min from SP + prevParams
				 * so that we can better assess each conflict.
				 */
				continue;
			}
			DataType type = field.type();
			if (type == IntegerDataType.dataType) {
				type = IntegerDataType.getUnsignedDataType(field.length(), dtm);
			}
			else if (type == PointerDataType.dataType) {
				type = new PointerTypedefBuilder(PointerDataType.dataType, dtm)
						.addressSpace(codeSpace)
						.build();
			}
			structure.replaceAtOffset(offset, type, field.length(), field.name(), "");
			undefined.remove(ULongSpan.extent(offset, field.length()));
		}
		for (ULongSpan undefSpan : undefined.spans()) {
			int spanLength = (int) undefSpan.length();
			DataType type = new ArrayDataType(DataType.DEFAULT, spanLength, 1, dtm);
			int offset = undefSpan.min().intValue();
			Address addr = min.add(offset);
			String fieldName = addr.getOffset() < 0
					? String.format("offset_0x%x", -addr.getOffset())
					: String.format("posOff_0x%x", addr.getOffset());
			structure.replaceAtOffset(offset, type, spanLength, fieldName, "");
		}
		return structure;
	}

	void processVar(Address address, String name, DataType type, int length, int scopeStart) {
		if (!address.isStackAddress()) {
			return;
		}
		Address varMax = address.add(length);
		if (varMax.compareTo(max) > 0) {
			max = varMax;
		}
		fields.put(address, new FrameField(address, name, type, length, scopeStart));
	}

	void processRegisterVar(Address address, String name, DataType dataType,
			Register register, int scopeStart) {
		processVar(address, name, dataType, register.getNumBytes(), scopeStart);
	}

	void processSavedRegister(Address address, Register register) {
		processRegisterVar(address, SAVED_REGISTER_FIELD_PREFIX + register.getName(),
			IntegerDataType.dataType,
			register, -1);
	}

	void processSaved(Map<Register, Address> saved) {
		for (Entry<Register, Address> entry : saved.entrySet()) {
			processSavedRegister(entry.getValue(), entry.getKey());
		}
	}

	void processOfReturn(Address address) {
		processRegisterVar(address, RETURN_ADDRESS_FIELD_NAME, PointerDataType.dataType, pc,
			Integer.MAX_VALUE);
	}

	void processFunction(Function function) {
		for (Variable variable : function.getStackFrame().getStackVariables()) {
			if (variable.getFirstUseOffset() > functionOffset) {
				continue;
			}
			processVariable(variable);
		}
	}

	String prependIfAbsent(String prefix, String name) {
		if (name.startsWith(prefix)) {
			return name;
		}
		return prefix + name;
	}

	void processVariable(Variable variable) {
		Varnode[] varnodes = variable.getVariableStorage().getVarnodes();
		String name = variable.getName();
		if (variable instanceof Parameter) {
			name = prependIfAbsent("param_", name);
		}
		else if (variable instanceof LocalVariable) {
			name = prependIfAbsent("local_", name);
		}
		else {
			throw new AssertionError();
		}
		if (varnodes.length == 1) {
			processVarnode(name, variable.getDataType(), varnodes[0],
				variable.getFirstUseOffset());
		}
		else {
			for (int i = 0; i < varnodes.length; i++) {
				processVarnode(name + "_pt" + i, IntegerDataType.dataType, varnodes[i],
					variable.getFirstUseOffset());
			}
		}
	}

	void processVarnode(String name, DataType type, Varnode vn, int scopeStart) {
		processVar(vn.getAddress(), name, type, vn.getSize(), scopeStart);
	}
}
