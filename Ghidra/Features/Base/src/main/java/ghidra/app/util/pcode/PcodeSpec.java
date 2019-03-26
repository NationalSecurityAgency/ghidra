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
package ghidra.app.util.pcode;

import ghidra.app.plugin.processors.sleigh.template.ConstTpl;
import ghidra.app.plugin.processors.sleigh.template.VarnodeTpl;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.exception.InvalidInputException;

import java.util.HashMap;
import java.util.List;

class PcodeSpec {

	//
	// Input Spec Flags
	//
	private static final int CONSTANT = 0x01;
	private static final int UNIQUE = 0x02;
	private static final int ADDRESS = 0x04;
	private static final int REGISTER = 0x08;
	private static final int RELATIVE_ADDRESS = 0x10;
	private static final int CUR_SPACE_POINTER = 0x20;

	//
	// Common Input Specs
	//

	private static final int ANY = CONSTANT | UNIQUE | ADDRESS | REGISTER | RELATIVE_ADDRESS;
	private static final int ANY_VARIABLE = UNIQUE | ADDRESS | REGISTER;

	private static final int[] NO_INPUT = new int[] {};
	private static final int[] ANY_ONE_INPUT = new int[] { ANY };
	private static final int[] ANY_TWO_INPUTS = new int[] { ANY, ANY };
	private static final int[] DIRECT_BRANCH_INPUTS = new int[] { CONSTANT | ADDRESS |
		RELATIVE_ADDRESS };
	private static final int[] DIRECT_CONDITIONAL_BRANCH_INPUTS = new int[] {
		CONSTANT | ADDRESS | RELATIVE_ADDRESS, ANY_VARIABLE };
	private static final int[] DIRECT_CALL_INPUTS = new int[] { ADDRESS };
	private static final int[] INDIRECT_FLOW_INPUTS = new int[] { UNIQUE | ADDRESS | REGISTER |
		RELATIVE_ADDRESS | CUR_SPACE_POINTER };
	private static final int[] LOAD_INPUTS = new int[] { CONSTANT, ANY };
	private static final int[] STORE_INPUTS = new int[] { CONSTANT, ANY, ANY };
	private static final int[] SHIFT_INPUTS = new int[] { ANY, CONSTANT };

	//
	// Output Type
	//
	private static final int OUTPUT_NONE = 0;
	private static final int OUTPUT_INPUT0_SIZE = 1;
	private static final int OUTPUT_INPUT0_SIZE_EXTENDED = 2;
	private static final int OUTPUT_INPUT0_SIZE_TRUNCATED = 3;
	private static final int OUTPUT_INPUT1_SIZE = 4;
	private static final int OUTPUT_BOOLEAN = 5;
	private static final int OUTPUT_ANY_SIZE = 6;

	private static HashMap<String, PcodeSpec> pcodeNameSpecMap;
	private static HashMap<Integer, PcodeSpec> pcodeSpecMap;

	private String opName;
	private int opCode;
	private int outputType;
	private boolean inputSizesMustMatch;
	private int[] inputSpecs;

	private PcodeSpec(String opName, int opCode, int outputType, boolean inputSizesMustMatch,
			int[] inputSpecs) {
		this.opName = opName;
		this.opCode = opCode;
		this.outputType = outputType;
		this.inputSizesMustMatch = inputSizesMustMatch;
		this.inputSpecs = inputSpecs;
	}

	boolean isAssignmentOp() {
		return outputType != 0;
	}

	boolean inputSizesMustMatch() {
		return inputSizesMustMatch;
	}

	String getOpName() {
		return opName;
	}

	int getOpCode() {
		return opCode;
	}

	int getNumInputs() {
		return inputSpecs.length;
	}

	void checkOutput(AddressFactory addrFactory, VarnodeTpl output, List<VarnodeTpl> inputs)
			throws InvalidInputException {

		if (outputType == OUTPUT_NONE) {
			if (output != null) {
				throw new InvalidInputException("operation " + opName +
					" does not support output assignment");
			}
			return;
		}
		else if (output == null) {
			throw new InvalidInputException("operation " + opName + " requires output assignment");
		}

		switch (outputType) {
			case OUTPUT_INPUT0_SIZE:
				if (inputs.size() == 0) {
					throw new InvalidInputException("operation " + opName + " input(s) are missing");
				}
				int inSize = getSize(addrFactory, inputs.get(0));
				int outSize = getSize(addrFactory, output);
				if (inSize != outSize) {
					throw new InvalidInputException("operation " + opName +
						" expected output size of " + inSize);
				}
				break;
			case OUTPUT_INPUT0_SIZE_EXTENDED:
				if (inputs.size() == 0) {
					throw new InvalidInputException("operation " + opName + " input(s) are missing");
				}
				inSize = getSize(addrFactory, inputs.get(0));
				outSize = getSize(addrFactory, output);
				if (inSize >= outSize) {
					throw new InvalidInputException("operation " + opName +
						" expected output size larger than " + inSize);
				}
				break;
			case OUTPUT_INPUT0_SIZE_TRUNCATED:
				if (inputs.size() == 0) {
					throw new InvalidInputException("operation " + opName + " input(s) are missing");
				}
				inSize = getSize(addrFactory, inputs.get(0));
				outSize = getSize(addrFactory, output);
				if (inSize <= outSize) {
					throw new InvalidInputException("operation " + opName +
						" expected output size smaller than " + inSize);
				}
				break;
			case OUTPUT_INPUT1_SIZE:
				if (inputs.size() < 2) {
					throw new InvalidInputException("operation " + opName + " input(s) are missing");
				}
				inSize = getSize(addrFactory, inputs.get(1));
				outSize = getSize(addrFactory, output);
				if (inSize != outSize) {
					throw new InvalidInputException("operation " + opName +
						" expected output size of " + inSize);
				}
				break;
			case OUTPUT_BOOLEAN:
				if (getSize(addrFactory, output) != 1) {
					throw new InvalidInputException("operation " + opName +
						" expected boolean output size of 1");
				}
				break;
			case OUTPUT_ANY_SIZE:
				break;
			default:
				throw new RuntimeException("unsupported output PcodeSpec output type");
		}
	}

	private int getSize(AddressFactory addrFactory, VarnodeTpl varnodeTpl) {
		ConstTpl size = varnodeTpl.getSize();
		if (size.getType() == ConstTpl.J_CURSPACE_SIZE) {
			return addrFactory.getDefaultAddressSpace().getAddressableUnitSize();
		}
		return (int) size.getReal();
	}

	/**
	 * Validate a specific varnode input template.
	 * @param addrFactory
	 * @param inputIndex
	 * @param input
	 * @param baselineSizeTpl size template for comparison when inputSizesMustMatch is true.  Check not performed if null.
	 * @return true if input is considered valid.
	 */
	void checkInput(AddressFactory addrFactory, int inputIndex, VarnodeTpl input,
			ConstTpl baselineSizeTpl) throws InvalidInputException {
		checkInputType(addrFactory, inputIndex, input);
		if (inputSizesMustMatch && baselineSizeTpl != null) {
			checkInputSize(addrFactory, inputIndex, input, baselineSizeTpl);
		}
	}

	private void checkInputSize(AddressFactory addrFactory, int inputIndex, VarnodeTpl input,
			ConstTpl baselineSizeTpl) throws InvalidInputException {
		int sizeType1 = baselineSizeTpl.getType();
		ConstTpl sizeTpl = input.getSize();
		int sizeType2 = sizeTpl.getType();
		AddressSpace defaultSpace = addrFactory.getDefaultAddressSpace(); // TODO: should really correspond to the CURRENT instruction space
		long size1 = sizeType1 == ConstTpl.J_CURSPACE_SIZE ? defaultSpace.getPointerSize()
				: baselineSizeTpl.getReal();
		long size2 = sizeType2 == ConstTpl.J_CURSPACE_SIZE ? defaultSpace.getPointerSize()
				: sizeTpl.getReal();
		if (size1 != size2) {
			throw new InvalidInputException("operation " + opName +
				" expected matching input size of " + size1);
		}
	}

	private void checkInputType(AddressFactory addrFactory, int inputIndex, VarnodeTpl input)
			throws InvalidInputException {

		int mask = inputSpecs[inputIndex];
		ConstTpl offset = input.getOffset();
		int offsetType = offset.getType();
		switch (offsetType) {
			case ConstTpl.REAL:
				ConstTpl space = input.getSpace();
				int spaceType = space.getType();
				if (spaceType == ConstTpl.SPACEID) {
					AddressSpace s = space.getSpaceId();
					if (space.isConstSpace()) {
						if ((mask & CONSTANT) == 0) {
							throw new InvalidInputException("operation " + opName +
								" - constant input not allowed");
						}
					}
					else if (space.isUniqueSpace()) {
						if ((mask & UNIQUE) == 0) {
							throw new InvalidInputException("operation " + opName +
								" unique variable input not allowed");
						}
					}
					else { // specific address or register space

						if (s == null) {
							throw new RuntimeException("address space not found");
						}
						if (s.isRegisterSpace()) {
							if ((mask & REGISTER) == 0) {
								throw new InvalidInputException("operation " + opName +
									" - register input not allowed");
							}
						}
						else {
							if ((mask & ADDRESS) == 0) {
								throw new InvalidInputException("operation " + opName +
									" - address input not allowed");
							}
						}
					}
					if ((mask & CUR_SPACE_POINTER) != 0) {
						ConstTpl size = input.getSize();
						int expectedSize = addrFactory.getDefaultAddressSpace().getPointerSize();
						if (size.getType() == ConstTpl.REAL && size.getReal() != expectedSize) {
							throw new InvalidInputException(
								"incorrect indirect pointer size, expected size of " + expectedSize);
						}
					}
				}
				else if (spaceType == ConstTpl.J_CURSPACE) {
					if ((mask & ADDRESS) == 0) {
						throw new InvalidInputException("operation " + opName +
							" - address input not allowed");
					}
				}
				else {
					throw new RuntimeException("unexpected space type (" + spaceType + ")");
				}
				break;

			case ConstTpl.J_START:
			case ConstTpl.J_NEXT:
				if ((mask & (ADDRESS | CONSTANT)) == 0) {
					throw new InvalidInputException("" + opName +
						" - address/constant input not allowed");
				}
				break;

			case ConstTpl.J_RELATIVE:
				if ((mask & RELATIVE_ADDRESS) == 0) {
					throw new InvalidInputException("" + opName +
						" - relative label input not allowed");
				}
				break;

			default:
				throw new RuntimeException("unsupported offset type (" + offsetType + ")");
		}
	}

	static PcodeSpec getSpec(String opName) {
		initMap();
		return pcodeNameSpecMap.get(opName.toUpperCase());
	}

	static PcodeSpec getSpec(int opCode) {
		initMap();
		return pcodeSpecMap.get(opCode);
	}

	private static void addSpec(String opName, int opCode, int outputType,
			boolean inputSizesMustMatch, int[] inputSpecs) {
		PcodeSpec opSpec = new PcodeSpec(opName, opCode, outputType, inputSizesMustMatch,
			inputSpecs);
		pcodeNameSpecMap.put(opName, opSpec);
		pcodeSpecMap.put(opCode, opSpec);
	}

	private static void initMap() {
		if (pcodeNameSpecMap != null) {
			return;
		}
		pcodeNameSpecMap = new HashMap<String, PcodeSpec>();
		pcodeSpecMap = new HashMap<Integer, PcodeSpec>();

		addSpec("unimpl", PcodeOp.UNIMPLEMENTED, OUTPUT_NONE, true, NO_INPUT);

		addSpec("COPY", PcodeOp.COPY, OUTPUT_INPUT0_SIZE, false, ANY_ONE_INPUT);
		addSpec("LOAD", PcodeOp.LOAD, OUTPUT_ANY_SIZE, false, LOAD_INPUTS);
		addSpec("STORE", PcodeOp.STORE, OUTPUT_NONE, false, STORE_INPUTS);
		addSpec("BRANCH", PcodeOp.BRANCH, OUTPUT_NONE, false, DIRECT_BRANCH_INPUTS);
		addSpec("CBRANCH", PcodeOp.CBRANCH, OUTPUT_NONE, false, DIRECT_CONDITIONAL_BRANCH_INPUTS);
		addSpec("BRANCHIND", PcodeOp.BRANCHIND, OUTPUT_NONE, false, INDIRECT_FLOW_INPUTS);
		addSpec("CALL", PcodeOp.CALL, OUTPUT_NONE, false, DIRECT_CALL_INPUTS);
		addSpec("CALLIND", PcodeOp.CALLIND, OUTPUT_NONE, false, INDIRECT_FLOW_INPUTS);
		addSpec("CALLOTHER", PcodeOp.CALLOTHER, OUTPUT_ANY_SIZE, false, null); // Special case !!
		addSpec("RETURN", PcodeOp.RETURN, OUTPUT_NONE, false, INDIRECT_FLOW_INPUTS);
		addSpec("INT_EQUAL", PcodeOp.INT_EQUAL, OUTPUT_BOOLEAN, true, ANY_TWO_INPUTS);
		addSpec("INT_NOTEQUAL", PcodeOp.INT_NOTEQUAL, OUTPUT_BOOLEAN, true, ANY_TWO_INPUTS);
		addSpec("INT_SLESS", PcodeOp.INT_SLESS, OUTPUT_BOOLEAN, true, ANY_TWO_INPUTS);
		addSpec("INT_SLESSEQUAL", PcodeOp.INT_SLESSEQUAL, OUTPUT_BOOLEAN, true, ANY_TWO_INPUTS);
		addSpec("INT_LESS", PcodeOp.INT_LESS, OUTPUT_BOOLEAN, true, ANY_TWO_INPUTS);
		addSpec("INT_LESSEQUAL", PcodeOp.INT_LESSEQUAL, OUTPUT_BOOLEAN, true, ANY_TWO_INPUTS);
		addSpec("INT_ZEXT", PcodeOp.INT_ZEXT, OUTPUT_INPUT0_SIZE_EXTENDED, false, ANY_ONE_INPUT);
		addSpec("INT_SEXT", PcodeOp.INT_SEXT, OUTPUT_INPUT0_SIZE_EXTENDED, false, ANY_ONE_INPUT);
		addSpec("INT_ADD", PcodeOp.INT_ADD, OUTPUT_INPUT0_SIZE, true, ANY_TWO_INPUTS);
		addSpec("INT_SUB", PcodeOp.INT_SUB, OUTPUT_INPUT0_SIZE, true, ANY_TWO_INPUTS);
		addSpec("INT_CARRY", PcodeOp.INT_CARRY, OUTPUT_BOOLEAN, true, ANY_TWO_INPUTS);
		addSpec("INT_SCARRY", PcodeOp.INT_SCARRY, OUTPUT_BOOLEAN, true, ANY_TWO_INPUTS);
		addSpec("INT_SBORROW", PcodeOp.INT_SBORROW, OUTPUT_BOOLEAN, true, ANY_TWO_INPUTS);
		addSpec("INT_2COMP", PcodeOp.INT_2COMP, OUTPUT_INPUT0_SIZE, false, ANY_ONE_INPUT);
		addSpec("INT_NEGATE", PcodeOp.INT_NEGATE, OUTPUT_INPUT0_SIZE, false, ANY_ONE_INPUT);
		addSpec("INT_XOR", PcodeOp.INT_XOR, OUTPUT_INPUT0_SIZE, true, ANY_TWO_INPUTS);
		addSpec("INT_AND", PcodeOp.INT_AND, OUTPUT_INPUT0_SIZE, true, ANY_TWO_INPUTS);
		addSpec("INT_OR", PcodeOp.INT_OR, OUTPUT_INPUT0_SIZE, true, ANY_TWO_INPUTS);
		addSpec("INT_LEFT", PcodeOp.INT_LEFT, OUTPUT_INPUT0_SIZE, false, SHIFT_INPUTS);
		addSpec("INT_RIGHT", PcodeOp.INT_RIGHT, OUTPUT_INPUT0_SIZE, false, SHIFT_INPUTS);
		addSpec("INT_SRIGHT", PcodeOp.INT_SRIGHT, OUTPUT_INPUT0_SIZE, false, SHIFT_INPUTS);
		addSpec("INT_MULT", PcodeOp.INT_MULT, OUTPUT_INPUT0_SIZE, true, ANY_TWO_INPUTS);
		addSpec("INT_DIV", PcodeOp.INT_DIV, OUTPUT_INPUT0_SIZE, true, ANY_TWO_INPUTS);
		addSpec("INT_SDIV", PcodeOp.INT_SDIV, OUTPUT_INPUT0_SIZE, true, ANY_TWO_INPUTS);
		addSpec("INT_REM", PcodeOp.INT_REM, OUTPUT_INPUT0_SIZE, true, ANY_TWO_INPUTS);
		addSpec("INT_SREM", PcodeOp.INT_SREM, OUTPUT_INPUT0_SIZE, true, ANY_TWO_INPUTS);
		addSpec("BOOL_NEGATE", PcodeOp.BOOL_NEGATE, OUTPUT_BOOLEAN, false, ANY_ONE_INPUT);
		addSpec("BOOL_XOR", PcodeOp.BOOL_XOR, OUTPUT_BOOLEAN, true, ANY_TWO_INPUTS);
		addSpec("BOOL_AND", PcodeOp.BOOL_AND, OUTPUT_BOOLEAN, true, ANY_TWO_INPUTS);
		addSpec("BOOL_OR", PcodeOp.BOOL_OR, OUTPUT_BOOLEAN, true, ANY_TWO_INPUTS);
		addSpec("FLOAT_EQUAL", PcodeOp.FLOAT_EQUAL, OUTPUT_BOOLEAN, true, ANY_TWO_INPUTS);
		addSpec("FLOAT_NOTEQUAL", PcodeOp.FLOAT_NOTEQUAL, OUTPUT_BOOLEAN, true, ANY_TWO_INPUTS);
		addSpec("FLOAT_LESS", PcodeOp.FLOAT_LESS, OUTPUT_BOOLEAN, true, ANY_TWO_INPUTS);
		addSpec("FLOAT_LESSEQUAL", PcodeOp.FLOAT_LESSEQUAL, OUTPUT_BOOLEAN, true, ANY_TWO_INPUTS);
		addSpec("FLOAT_NAN", PcodeOp.FLOAT_NAN, OUTPUT_BOOLEAN, false, ANY_ONE_INPUT);
		addSpec("FLOAT_ADD", PcodeOp.FLOAT_ADD, OUTPUT_INPUT0_SIZE, true, ANY_TWO_INPUTS);
		addSpec("FLOAT_DIV", PcodeOp.FLOAT_DIV, OUTPUT_INPUT0_SIZE, true, ANY_TWO_INPUTS);
		addSpec("FLOAT_MULT", PcodeOp.FLOAT_MULT, OUTPUT_INPUT0_SIZE, true, ANY_TWO_INPUTS);
		addSpec("FLOAT_SUB", PcodeOp.FLOAT_SUB, OUTPUT_INPUT0_SIZE, true, ANY_TWO_INPUTS);
		addSpec("FLOAT_NEG", PcodeOp.FLOAT_NEG, OUTPUT_INPUT0_SIZE, false, ANY_ONE_INPUT);
		addSpec("FLOAT_ABS", PcodeOp.FLOAT_ABS, OUTPUT_INPUT0_SIZE, false, ANY_ONE_INPUT);
		addSpec("FLOAT_SQRT", PcodeOp.FLOAT_SQRT, OUTPUT_INPUT0_SIZE, false, ANY_ONE_INPUT);
		addSpec("INT2FLOAT", PcodeOp.FLOAT_INT2FLOAT, OUTPUT_INPUT0_SIZE, false, ANY_ONE_INPUT);
		addSpec("FLOAT2FLOAT", PcodeOp.FLOAT_FLOAT2FLOAT, OUTPUT_INPUT0_SIZE, false, ANY_ONE_INPUT);
		addSpec("FLOAT2INT", PcodeOp.FLOAT_TRUNC, OUTPUT_INPUT0_SIZE, false, ANY_ONE_INPUT);
		addSpec("FLOAT_CEIL", PcodeOp.FLOAT_CEIL, OUTPUT_INPUT0_SIZE, false, ANY_ONE_INPUT);
		addSpec("FLOAT_FLOOR", PcodeOp.FLOAT_FLOOR, OUTPUT_INPUT0_SIZE, false, ANY_ONE_INPUT);
		addSpec("FLOAT_ROUND", PcodeOp.FLOAT_ROUND, OUTPUT_INPUT0_SIZE, false, ANY_ONE_INPUT);
		addSpec("PIECE", PcodeOp.PIECE, OUTPUT_ANY_SIZE, true, SHIFT_INPUTS); // TODO: INPUTS ??
		addSpec("SUBPIECE", PcodeOp.SUBPIECE, OUTPUT_ANY_SIZE, false, SHIFT_INPUTS);
		addSpec("CPOOL", PcodeOp.CPOOLREF, OUTPUT_ANY_SIZE, false, SHIFT_INPUTS);
		addSpec("NEWOBJECT", PcodeOp.NEW, OUTPUT_ANY_SIZE, false, null);
	}

}
