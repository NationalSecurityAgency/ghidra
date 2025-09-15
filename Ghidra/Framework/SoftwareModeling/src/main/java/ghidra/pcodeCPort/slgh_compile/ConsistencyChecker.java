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
package ghidra.pcodeCPort.slgh_compile;

import java.util.*;
import java.util.Map.Entry;

import generic.stl.IteratorSTL;
import generic.stl.VectorSTL;
import ghidra.pcodeCPort.context.SleighError;
import ghidra.pcodeCPort.opcodes.OpCode;
import ghidra.pcodeCPort.semantics.*;
import ghidra.pcodeCPort.semantics.ConstTpl.const_type;
import ghidra.pcodeCPort.semantics.ConstTpl.v_field;
import ghidra.pcodeCPort.sleighbase.SleighBase;
import ghidra.pcodeCPort.slghsymbol.*;
import ghidra.pcodeCPort.space.AddrSpace;

class ConsistencyChecker {

	private int unnecessarypcode;
	private int readnowrite;
	private int writenoread;

	private int largetemp;			// number of constructors using a temporary varnode larger than SleighBase.MAX_UNIQUE_SIZE
	private int largeint;			// number of constructors that exports constant integers larger then the export size
	private boolean printextwarning;
	private boolean printdeadwarning;
	private boolean printlargetempwarning;	// if true, warning about temporary varnodes larger than SleighBase.MAX_UNIQUE_SIZE 
	private boolean printlargeintwarning;	// if true, warning about interger larger then the export size
	private SleighCompile compiler;
	private SubtableSymbol root_symbol;
	private List<SubtableSymbol> postorder = new ArrayList<>();

	// Sizes associated with tables
	private Map<SubtableSymbol, Integer> sizemap = new HashMap<>();

	private OperandSymbol getOperandSymbol(int slot, OpTpl op, Constructor ct) {
		VarnodeTpl vn;
		OperandSymbol opsym = null;
		int handindex;

		if (slot == -1) {
			vn = op.getOut();
		}
		else {
			vn = op.getIn(slot);
		}

		switch (vn.getSize().getType()) {
			case handle:
				handindex = vn.getSize().getHandleIndex();
				opsym = ct.getOperand(handindex);
				break;
			default:
				break;
		}
		return opsym;
	}

	private boolean sizeRestriction(OpTpl op, Constructor ct) {
		// Make sure op template meets size restrictions
		// Return false and any info about mismatched sizes
		int vnout, vn0, vn1;
		AddrSpace spc;

		switch (op.getOpcode()) {
			case CPUI_COPY:			// Instructions where all inputs and output are same size
			case CPUI_INT_2COMP:
			case CPUI_INT_NEGATE:
			case CPUI_FLOAT_NEG:
			case CPUI_FLOAT_ABS:
			case CPUI_FLOAT_SQRT:
			case CPUI_FLOAT_CEIL:
			case CPUI_FLOAT_FLOOR:
			case CPUI_FLOAT_ROUND:
				vnout = recoverSize(op.getOut().getSize(), ct);
				if (vnout == -1) {
					printOpError(op, ct, -1, -1, "Using subtable with exports in expression");
					return false;
				}
				vn0 = recoverSize(op.getIn(0).getSize(), ct);
				if (vn0 == -1) {
					printOpError(op, ct, 0, 0, "Using subtable with exports in expression");
					return false;
				}
				if (vnout == vn0) {
					return true;
				}
				if ((vnout == 0) || (vn0 == 0)) {
					return true;
				}
				printOpError(op, ct, -1, 0, "Input and output sizes must match; " +
					op.getIn(0).getSize() + " != " + op.getOut().getSize());
				return false;
			case CPUI_INT_ADD:
			case CPUI_INT_SUB:
			case CPUI_INT_XOR:
			case CPUI_INT_AND:
			case CPUI_INT_OR:
			case CPUI_INT_MULT:
			case CPUI_INT_DIV:
			case CPUI_INT_SDIV:
			case CPUI_INT_REM:
			case CPUI_INT_SREM:
			case CPUI_FLOAT_ADD:
			case CPUI_FLOAT_DIV:
			case CPUI_FLOAT_MULT:
			case CPUI_FLOAT_SUB:
				vnout = recoverSize(op.getOut().getSize(), ct);
				if (vnout == -1) {
					printOpError(op, ct, -1, -1, "Using subtable with exports in expression");
					return false;
				}
				vn0 = recoverSize(op.getIn(0).getSize(), ct);
				if (vn0 == -1) {
					printOpError(op, ct, 0, 0, "Using subtable with exports in expression");
					return false;
				}
				vn1 = recoverSize(op.getIn(1).getSize(), ct);
				if (vn1 == -1) {
					printOpError(op, ct, 1, 1, "Using subtable with exports in expression");
					return false;
				}
				if ((vnout != 0) && (vn0 != 0) && (vnout != vn0)) {
					printOpError(op, ct, -1, 0, "The output and all input sizes must match");
					return false;
				}
				if ((vnout != 0) && (vn1 != 0) && (vnout != vn1)) {
					printOpError(op, ct, -1, 1, "The output and all input sizes must match");
					return false;
				}
				if ((vn0 != 0) && (vn1 != 0) && (vn0 != vn1)) {
					printOpError(op, ct, 0, 1, "The output and all input sizes must match");
					return false;
				}
				return true;
			case CPUI_FLOAT_NAN:
				vnout = recoverSize(op.getOut().getSize(), ct);
				if (vnout == -1) {
					printOpError(op, ct, -1, -1, "Using subtable with exports in expression");
					return false;
				}
				if (vnout != 1) {
					printOpError(op, ct, -1, -1, "Output must be a boolean (size 1)");
					return false;
				}
				break;
			case CPUI_INT_EQUAL:		// Instructions with bool output, all inputs equal size
			case CPUI_INT_NOTEQUAL:
			case CPUI_INT_SLESS:
			case CPUI_INT_SLESSEQUAL:
			case CPUI_INT_LESS:
			case CPUI_INT_LESSEQUAL:
			case CPUI_INT_CARRY:
			case CPUI_INT_SCARRY:
			case CPUI_INT_SBORROW:
			case CPUI_FLOAT_EQUAL:
			case CPUI_FLOAT_NOTEQUAL:
			case CPUI_FLOAT_LESS:
			case CPUI_FLOAT_LESSEQUAL:
				vnout = recoverSize(op.getOut().getSize(), ct);
				if (vnout == -1) {
					printOpError(op, ct, -1, -1, "Using subtable with exports in expression");
					return false;
				}
				if (vnout != 1) {
					printOpError(op, ct, -1, -1, "Output must be a boolean (size 1)");
					return false;
				}
				vn0 = recoverSize(op.getIn(0).getSize(), ct);
				if (vn0 == -1) {
					printOpError(op, ct, 0, 0, "Using subtable with exports in expression");
					return false;
				}
				vn1 = recoverSize(op.getIn(1).getSize(), ct);
				if (vn1 == -1) {
					printOpError(op, ct, 1, 1, "Using subtable with exports in expression");
					return false;
				}
				if ((vn0 == 0) || (vn1 == 0)) {
					return true;
				}
				if (vn0 != vn1) {
					printOpError(op, ct, 0, 1, "Inputs must be the same size");
					return false;
				}
				return true;
			case CPUI_BOOL_XOR:
			case CPUI_BOOL_AND:
			case CPUI_BOOL_OR:
				vnout = recoverSize(op.getOut().getSize(), ct);
				if (vnout == -1) {
					printOpError(op, ct, -1, -1, "Using subtable with exports in expression");
					return false;
				}
				if (vnout != 1) {
					printOpError(op, ct, -1, -1, "Output must be a boolean (size 1)");
					return false;
				}
				vn0 = recoverSize(op.getIn(0).getSize(), ct);
				if (vn0 == -1) {
					printOpError(op, ct, 0, 0, "Using subtable with exports in expression");
					return false;
				}
				if (vn0 != 1) {
					printOpError(op, ct, 0, 0, "Input must be a boolean (size 1)");
					return false;
				}
				return true;
			case CPUI_BOOL_NEGATE:
				vnout = recoverSize(op.getOut().getSize(), ct);
				if (vnout == -1) {
					printOpError(op, ct, -1, -1, "Using subtable with exports in expression");
					return false;
				}
				if (vnout != 1) {
					printOpError(op, ct, -1, -1, "Output must be a boolean (size 1)");
					return false;
				}
				vn0 = recoverSize(op.getIn(0).getSize(), ct);
				if (vn0 == -1) {
					printOpError(op, ct, 0, 0, "Using subtable with exports in expression");
					return false;
				}
				if (vn0 != 1) {
					printOpError(op, ct, 0, 0, "Input must be a boolean (size 1)");
					return false;
				}
				return true;
			// The shift amount does not necessarily have to be the same size
			// But the output and first parameter must be same size
			case CPUI_INT_LEFT:
			case CPUI_INT_RIGHT:
			case CPUI_INT_SRIGHT:
				vnout = recoverSize(op.getOut().getSize(), ct);
				if (vnout == -1) {
					printOpError(op, ct, -1, -1, "Using subtable with exports in expression");
					return false;
				}
				vn0 = recoverSize(op.getIn(0).getSize(), ct);
				if (vn0 == -1) {
					printOpError(op, ct, 0, 0, "Using subtable with exports in expression");
					return false;
				}
				if ((vnout == 0) || (vn0 == 0)) {
					return true;
				}
				if (vnout != vn0) {
					printOpError(op, ct, -1, 0, "Output and first input must be the same size");
					return false;
				}
				return true;
			case CPUI_INT_ZEXT:
			case CPUI_INT_SEXT:
				vnout = recoverSize(op.getOut().getSize(), ct);
				if (vnout == -1) {
					printOpError(op, ct, -1, -1, "Using subtable with exports in expression");
					return false;
				}
				vn0 = recoverSize(op.getIn(0).getSize(), ct);
				if (vn0 == -1) {
					printOpError(op, ct, 0, 0, "Using subtable with exports in expression");
					return false;
				}
				if ((vnout == 0) || (vn0 == 0)) {
					return true;
				}
				if (vnout == vn0) {
					dealWithUnnecessaryExt(op, ct);
					return true;
				}
				else if (vnout < vn0) {
					printOpError(op, ct, -1, 0,
						"Output size must be strictly bigger than input size");
					return false;
				}
				return true;
			case CPUI_CBRANCH:
				vn1 = recoverSize(op.getIn(1).getSize(), ct);
				if (vn1 == -1) {
					printOpError(op, ct, 1, 1, "Using subtable with exports in expression");
					return false;
				}
				if (vn1 != 1) {
					printOpError(op, ct, 1, 1, "Input must be a boolean (size 1)");
					return false;
				}
				return true;
			case CPUI_LOAD:
			case CPUI_STORE:
				if (op.getIn(0).getOffset().getType() != ConstTpl.const_type.spaceid) {
					return true;
				}
				spc = op.getIn(0).getOffset().getSpace();
				vn1 = recoverSize(op.getIn(1).getSize(), ct);
				if (vn1 == -1) {
					printOpError(op, ct, 1, 1, "Using subtable with exports in expression");
					return false;
				}
				if ((vn1 != 0) && (vn1 != spc.getAddrSize())) {
					printOpError(op, ct, 1, 1, "Pointer size must match size of space");
					return false;
				}
				return true;
			case CPUI_SUBPIECE:
				vnout = recoverSize(op.getOut().getSize(), ct);
				if (vnout == -1) {
					printOpError(op, ct, -1, -1, "Using subtable with exports in expression");
					return false;
				}
				vn0 = recoverSize(op.getIn(0).getSize(), ct);
				if (vn0 == -1) {
					printOpError(op, ct, 0, 0, "Using subtable with exports in expression");
					return false;
				}
				vn1 = (int) op.getIn(1).getOffset().getReal();
				if ((vnout == 0) || (vn0 == 0)) {
					return true;
				}
				if ((vnout == vn0) && (vn1 == 0)) { // No actual truncation is occurring
					dealWithUnnecessaryTrunc(op, ct);
					return true;
				}
				else if (vnout >= vn0) {
					printOpError(op, ct, -1, 0, "Output must be strictly smaller than input");
					return false;
				}
				if (vnout > vn0 - vn1) {
					printOpError(op, ct, -1, 0, "Too much truncation");
					return false;
				}
				return true;
			default:
				break;
		}
		return true;
	}

	private String getOpName(OpTpl op) {
		switch (op.getOpcode()) {
			case CPUI_COPY:
				return "Copy(=)";
			case CPUI_LOAD:
				return "Load(*)";
			case CPUI_STORE:
				return "Store(*)";
			case CPUI_BRANCH:
				return "Branch(goto)";
			case CPUI_CBRANCH:
				return "Conditional branch(if)";
			case CPUI_BRANCHIND:
				return "Indirect branch(goto[])";
			case CPUI_CALL:
				return "Call";
			case CPUI_CALLIND:
				return "Indirect Call";
			case CPUI_CALLOTHER:
				return "User defined";
			case CPUI_RETURN:
				return "Return";
			case CPUI_INT_EQUAL:
				return "Equality(==)";
			case CPUI_INT_NOTEQUAL:
				return "Notequal(!=)";
			case CPUI_INT_SLESS:
				return "Signed less than(s<)";
			case CPUI_INT_SLESSEQUAL:
				return "Signed less than or equal(s<=)";
			case CPUI_INT_LESS:
				return "Less than(<)";
			case CPUI_INT_LESSEQUAL:
				return "Less than or equal(<=)";
			case CPUI_INT_ZEXT:
				return "Zero extension(zext)";
			case CPUI_INT_SEXT:
				return "Signed extension(sext)";
			case CPUI_INT_ADD:
				return "Addition(+)";
			case CPUI_INT_SUB:
				return "Subtraction(-)";
			case CPUI_INT_CARRY:
				return "Carry";
			case CPUI_INT_SCARRY:
				return "Signed carry";
			case CPUI_INT_SBORROW:
				return "Signed borrow";
			case CPUI_INT_2COMP:
				return "Twos complement(-)";
			case CPUI_INT_NEGATE:
				return "Negate(~)";
			case CPUI_INT_XOR:
				return "Exclusive or(^)";
			case CPUI_INT_AND:
				return "And(&)";
			case CPUI_INT_OR:
				return "Or(|)";
			case CPUI_INT_LEFT:
				return "Left shift(<<)";
			case CPUI_INT_RIGHT:
				return "Right shift(>>)";
			case CPUI_INT_SRIGHT:
				return "Signed right shift(s>>)";
			case CPUI_INT_MULT:
				return "Multiplication(*)";
			case CPUI_INT_DIV:
				return "Division(/)";
			case CPUI_INT_SDIV:
				return "Signed division(s/)";
			case CPUI_INT_REM:
				return "Remainder(%)";
			case CPUI_INT_SREM:
				return "Signed remainder(s%)";
			case CPUI_BOOL_NEGATE:
				return "Boolean negate(!)";
			case CPUI_BOOL_XOR:
				return "Boolean xor(^^)";
			case CPUI_BOOL_AND:
				return "Boolean and(&&)";
			case CPUI_BOOL_OR:
				return "Boolean or(||)";
			case CPUI_FLOAT_EQUAL:
				return "Float equal(f==)";
			case CPUI_FLOAT_NOTEQUAL:
				return "Float notequal(f!=)";
			case CPUI_FLOAT_LESS:
				return "Float less than(f<)";
			case CPUI_FLOAT_LESSEQUAL:
				return "Float less than or equal(f<=)";
			case CPUI_FLOAT_NAN:
				return "Not a number(nan)";
			case CPUI_FLOAT_ADD:
				return "Float addition(f+)";
			case CPUI_FLOAT_DIV:
				return "Float division(f/)";
			case CPUI_FLOAT_MULT:
				return "Float multiplication(f*)";
			case CPUI_FLOAT_SUB:
				return "Float subtractions(f-)";
			case CPUI_FLOAT_NEG:
				return "Float minus(f-)";
			case CPUI_FLOAT_ABS:
				return "Absolute value(abs)";
			case CPUI_FLOAT_SQRT:
				return "Square root";
			case CPUI_FLOAT_INT2FLOAT:
				return "Integer to float conversion(int2float)";
			case CPUI_FLOAT_FLOAT2FLOAT:
				return "Float to float conversion(float2float)";
			case CPUI_FLOAT_TRUNC:
				return "Float truncation(trunc)";
			case CPUI_FLOAT_CEIL:
				return "Ceiling(ceil)";
			case CPUI_FLOAT_FLOOR:
				return "Floor";
			case CPUI_FLOAT_ROUND:
				return "Round";
			case CPUI_MULTIEQUAL:
				return "Build";
			case CPUI_INDIRECT:
				return "Delay";
			case CPUI_SUBPIECE:
				return "Truncation(:)";
			case CPUI_SEGMENTOP:
				return "Segment table(segment)";
			case CPUI_CPOOLREF:
				return "Constant Pool(cpool)";
			case CPUI_NEW:
				return "New object(newobject)";
			default:
				return "";
		}
	}

	private void printOpError(OpTpl op, Constructor ct, int err1, int err2, String message) {
		SubtableSymbol sym = ct.getParent();
		OperandSymbol op1, op2;

		op1 = getOperandSymbol(err1, op, ct);
		if (err2 != err1) {
			op2 = getOperandSymbol(err2, op, ct);
		}
		else {
			op2 = null;
		}

		StringBuilder sb = new StringBuilder();
		sb.append("Size restriction error in table '")
				.append(sym.getName())
				.append("' in constructor at ")
				.append(ct.location)
				.append("\n");

		sb.append("  Problem");
		if ((op1 != null) && (op2 != null)) {
			sb.append(" with '" + op1.getName() + "' and '" + op2.getName() + "'");
		}
		else if (op1 != null) {
			sb.append(" with '" + op1.getName() + "'");
		}
		else if (op2 != null) {
			sb.append(" with '" + op2.getName() + "'");
		}
		sb.append(" in '" + getOpName(op) + "' operator");

		sb.append("\n  ").append(message);

		compiler.reportError(op.location, sb.toString());

	}

	private int recoverSize(ConstTpl sizeconst, Constructor ct) {
		return switch (sizeconst.getType()) {
			case real -> (int) sizeconst.getReal();
			case handle -> {
				int handindex = sizeconst.getHandleIndex();
				OperandSymbol opsym = ct.getOperand(handindex);
				int size = opsym.getSize();
				if (size != -1) {
					yield size;
				}

				TripleSymbol definingSymbol = opsym.getDefiningSymbol();
				if (!(definingSymbol instanceof SubtableSymbol tabsym)) {
					throw new SleighError("Could not recover varnode template size",
						ct.location);
				}
				Integer symsize = sizemap.get(tabsym);
				if (symsize == null) {
					throw new SleighError("Subtable out of order", ct.location);
				}
				yield symsize;
			}
			default -> throw new SleighError("Bad constant type as varnode template size",
				ct.location);
		};
	}

	private void handle(String msg, Constructor ct) {
		compiler.reportWarning(ct.location, " Unsigned comparison with " + msg + " in constructor");
	}

	private void handleZero(String trueOrFalse, Constructor ct) {
		handle("zero is always " + trueOrFalse, ct);
	}

	private void handleConstants(Constructor ct) {
		handle("constants should be pre-computed", ct);
	}

	private void handleBetter(String msg, Constructor ct) {
		handle("zero might be better written as \"" + msg +
			"\" (or did you mean to use signed comparison?)", ct);
	}

	private boolean checkOpMisuse(OpTpl op, Constructor ct) {
		switch (op.getOpcode()) {
			case CPUI_INT_LESS -> {
				VarnodeTpl vn0 = op.getIn(0);
				VarnodeTpl vn1 = op.getIn(1);
				if (vn1.getSpace().isConstSpace()) {
					if (vn1.getOffset().isZero()) {
						handleZero("false", ct);
					}
					else if (vn0.getSpace().isConstSpace()) {
						if (vn0.getOffset().isZero()) {
							handleZero("true", ct);
						}
						else {
							handleConstants(ct);
						}
					}
				}
				else if (vn0.getSpace().isConstSpace() && vn0.getOffset().isZero()) {
					handleBetter("!= 0", ct);
				}
			}
			case CPUI_INT_LESSEQUAL -> {
				VarnodeTpl vn0 = op.getIn(0);
				VarnodeTpl vn1 = op.getIn(1);
				if (vn0.getSpace().isConstSpace()) {
					if (vn0.getOffset().isZero()) {
						handleZero("true", ct);
					}
					else if (vn1.getSpace().isConstSpace()) {
						if (vn1.getOffset().isZero()) {
							handleZero("false", ct);
						}
						else {
							handleConstants(ct);
						}
					}
				}
				else if (vn1.getSpace().isConstSpace() && vn1.getOffset().isZero()) {
					handleBetter("== 0", ct);
				}
			}
			default -> {
			}
		}
		return true;
	}

	private boolean checkConstructorSection(Constructor ct, ConstructTpl cttpl) {
		// Check all the OpTpl s within the given section for consistency, return true if all tests pass
		if (cttpl == null) {
			return true;		// Nothing to check
		}
		IteratorSTL<OpTpl> iter;
		VectorSTL<OpTpl> ops = cttpl.getOpvec();
		boolean testresult = true;

		for (iter = ops.begin(); !iter.isEnd(); iter.increment()) {
			if (!sizeRestriction(iter.get(), ct)) {
				testresult = false;
			}
			if (!checkOpMisuse(iter.get(), ct)) {
				testresult = false;
			}
		}
		return testresult;
	}

	/**
	 * Returns true precisely when {@code opTpl} uses a {@link VarnodeTpl} in the unique space whose
	 * size is larger than {@link SleighBase#MAX_UNIQUE_SIZE}. Note that this method returns as soon
	 * as one large {@link VarnodeTpl} is found.
	 * 
	 * @param opTpl the op to check
	 * @return true if {@code opTpl} uses a large temporary varnode
	 */
	private boolean hasLargeTemporary(OpTpl opTpl) {
		VarnodeTpl out = opTpl.getOut();
		if (out != null && isTemporaryAndTooBig(out)) {
			return true;
		}
		for (int i = 0; i < opTpl.numInput(); ++i) {
			VarnodeTpl in = opTpl.getIn(i);
			if (isTemporaryAndTooBig(in)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Returns true precisely when {@code vn} is in the unique space and has a size larger than
	 * {@link SleighBase#MAX_UNIQUE_SIZE}.
	 * 
	 * @param vn varnode template to check
	 * @return true if it uses a large temporary
	 */
	private boolean isTemporaryAndTooBig(VarnodeTpl vn) {
		return vn.getSpace().isUniqueSpace() && vn.getSize().getReal() > SleighBase.MAX_UNIQUE_SIZE;
	}

	private boolean checkVarnodeTruncation(Constructor ct, int slot, OpTpl op, VarnodeTpl vn,
			boolean isbigendian) {
		ConstTpl off = vn.getOffset();
		if (off.getType() != const_type.handle) {
			return true;
		}
		if (off.getSelect() != v_field.v_offset_plus) {
			return true;
		}
		const_type sztype = vn.getSize().getType();
		if ((sztype != const_type.real) && (sztype != const_type.handle)) {
			printOpError(op, ct, slot, slot, "Bad truncation expression");
			return false;
		}
		int sz = recoverSize(off, ct);		// Recover the size of the original operand
		if (sz <= 0) {
			printOpError(op, ct, slot, slot, "Could not recover size");
			return false;
		}
		boolean res = vn.adjustTruncation(sz, isbigendian);
		if (!res) {
			printOpError(op, ct, slot, slot, "Truncation operator out of bounds");
			return false;
		}
		return true;
	}

	private boolean checkSectionTruncations(Constructor ct, ConstructTpl cttpl,
			boolean isbigendian) {
		// Check all the varnodes that have an offset_plus template
		//     adjust the plus if we are big endian
		//     make sure the truncation is valid
		VectorSTL<OpTpl> ops = cttpl.getOpvec();
		boolean testresult = true;
		Iterator<OpTpl> iter;

		iter = ops.iterator();
		while (iter.hasNext()) {
			OpTpl op = iter.next();
			VarnodeTpl outvn = op.getOut();
			if (outvn != null) {
				if (!checkVarnodeTruncation(ct, -1, op, outvn, isbigendian)) {
					testresult = false;
				}
			}
			for (int i = 0; i < op.numInput(); ++i) {
				if (!checkVarnodeTruncation(ct, i, op, op.getIn(i), isbigendian)) {
					testresult = false;
				}
			}
		}
		return testresult;
	}

	private boolean checkSubtable(SubtableSymbol sym) {
		int tablesize = -1;
		int numconstruct = sym.getNumConstructors();
		Constructor ct;
		boolean testresult = true;
		boolean seenemptyexport = false;
		boolean seennonemptyexport = false;

		for (int i = 0; i < numconstruct; ++i) {
			ct = sym.getConstructor(i);
			if (!checkConstructorSection(ct, ct.getTempl())) {
				testresult = false;
			}
			int numsection = ct.getNumSections();
			for (int j = 0; j < numsection; ++j) {
				if (!checkConstructorSection(ct, ct.getNamedTempl(j))) {
					testresult = false;
				}
			}

			if (ct.getTempl() == null) {
				continue;
			}	// Unimplemented
			HandleTpl exportres = ct.getTempl().getResult();
			if (exportres != null) {
				if (seenemptyexport && (!seennonemptyexport)) {
					compiler.reportError(ct.location, String.format(
						"Table '%s' exports inconsistently; Constructor at %s is first inconsitency",
						sym.getName(), ct.location));
					testresult = false;
				}
				seennonemptyexport = true;
				int exsize = recoverSize(exportres.getSize(), ct);
				if (tablesize == -1) {
					tablesize = exsize;
				}
				if (exsize != tablesize) {
					compiler.reportError(ct.location, String.format(
						"Table '%s' has inconsistent export size; Constructor at %s is first conflict",
						sym.getName(), ct.location));
					testresult = false;
				}
			}
			else {
				if (seennonemptyexport && (!seenemptyexport)) {
					compiler.reportError(ct.location, String.format(
						"Table '%s' exports inconsistently; Constructor at %s is first inconsitency",
						sym.getName(), ct.location));
					testresult = false;
				}
				seenemptyexport = true;
			}
		}
		if (seennonemptyexport) {
			if (tablesize == 0) {
				compiler.reportWarning(sym.location,
					"Table '" + sym.getName() + "' exports size 0");

			}
			sizemap.put(sym, tablesize);	// Remember recovered size
		}
		else {
			sizemap.put(sym, -1);
		}

		return testresult;
	}

	// Deal with detected extension (SEXT or ZEXT) where the
	// input size is the same as the output size
	private void dealWithUnnecessaryExt(OpTpl op, Constructor ct) {
		if (printextwarning) {
			compiler.reportWarning(op.location, "Unnecessary '" + getOpName(op) + "'");
		}
		op.setOpcode(OpCode.CPUI_COPY); // Equivalent to copy
		unnecessarypcode += 1;
	}

	private void dealWithUnnecessaryTrunc(OpTpl op, Constructor ct) {
		if (printextwarning) {
			compiler.reportWarning(op.location, "Unnecessary '" + getOpName(op) + "'");
		}
		op.setOpcode(OpCode.CPUI_COPY); // Equivalent to copy
		op.removeInput(1);
		unnecessarypcode += 1;
	}

	// Establish table ordering
	private void setPostOrder(SubtableSymbol root) {
		postorder.clear();
		sizemap.clear();

		// Establish post-order of SubtableSymbols so that we can
		// recursively fill in sizes of varnodes which are exported
		// from constructors

		VectorSTL<SubtableSymbol> path = new VectorSTL<>();
		VectorSTL<Integer> state = new VectorSTL<>();
		VectorSTL<Integer> ctstate = new VectorSTL<>();

		sizemap.put(root, -1); // Mark root as traversed
		path.push_back(root);
		state.push_back(0);
		ctstate.push_back(0);

		while (!path.empty()) {
			SubtableSymbol cur = path.back();
			int ctind = state.back();
			if (ctind >= cur.getNumConstructors()) {
				path.pop_back(); // Table is fully traversed
				state.pop_back();
				ctstate.pop_back();
				postorder.add(cur); // Post the traversed table
			}
			else {
				Constructor ct = cur.getConstructor(ctind);
				int oper = ctstate.back();
				if (oper >= ct.getNumOperands()) {
					state.setBack(ctind + 1); // Constructor fully traversed
					ctstate.setBack(0);
				}
				else {
					ctstate.setBack(oper + 1);
					OperandSymbol opsym = ct.getOperand(oper);
					TripleSymbol definingSymbol = opsym.getDefiningSymbol();
					if (definingSymbol instanceof SubtableSymbol subsym) {
						Integer symsize = sizemap.get(subsym);
						if (symsize == null) { // Not traversed yet
							sizemap.put(subsym, -1); // Mark table as
							// traversed
							path.push_back(subsym); // Recurse
							state.push_back(0);
							ctstate.push_back(0);
						}
					}
				}
			}
		}
	}

	static class UniqueState {
		NavigableMap<Long, OptimizeRecord> recs = new TreeMap<>();

		private static long endOf(Entry<Long, OptimizeRecord> entry) {
			return entry.getKey() + entry.getValue().size;
		}

		public void clear() {
			recs.clear();
		}

		/**
		 * Combine all the given entries into one, where the varnode is the union of all the given
		 * varnodes.
		 * 
		 * <p>
		 * NOTE: There may be a weird case where two neighboring varnodes are read, then later they
		 * get coalesced in a write. This would indicate the combined varnode is read twice, which
		 * is not exactly correct. However, the optimizer would exclude that case, anyway.
		 * 
		 * @param records the entries
		 * @return the coalesced entry
		 */
		private OptimizeRecord coalesce(List<OptimizeRecord> records) {
			long minOff = -1;
			long maxOff = -1;
			for (OptimizeRecord rec : records) {
				if (minOff == -1 || rec.offset < minOff) {
					minOff = rec.offset;
				}
				if (maxOff == -1 || rec.offset + rec.size > maxOff) {
					maxOff = rec.offset + rec.size;
				}
			}
			OptimizeRecord result = new OptimizeRecord(minOff, (int) (maxOff - minOff));
			for (OptimizeRecord rec : records) {
				result.updateCombine(rec);
			}
			return result;
		}

		private void set(long offset, int size, OptimizeRecord rec) {
			List<OptimizeRecord> records = getDefinitions(offset, size);
			records.add(rec);
			OptimizeRecord coalesced = coalesce(records);
			recs.subMap(coalesced.offset, coalesced.offset + coalesced.size).clear();
			recs.put(coalesced.offset, coalesced);
		}

		private List<OptimizeRecord> getDefinitions(long offset, int size) {
			if (size == 0) {
				size = 1;
			}
			List<OptimizeRecord> result = new ArrayList<>();
			Entry<Long, OptimizeRecord> preEntry = recs.lowerEntry(offset);
			long cursor = offset;
			if (preEntry != null && endOf(preEntry) > offset) {
				OptimizeRecord preRec = preEntry.getValue();
				// No need to truncate, as we're just counting a read
				// Do not overwrite in map for reads
				cursor = endOf(preEntry);
				// Make an immutable copy of the entry.
				result.add(preRec);
			}
			long end = offset + size;
			Map<Long, OptimizeRecord> toPut = new HashMap<>();
			for (Entry<Long, OptimizeRecord> entry : recs.subMap(offset, end).entrySet()) {
				if (entry.getKey() > cursor) {
					// This will certainly cause an error report. Good.
					OptimizeRecord missing =
						new OptimizeRecord(cursor, (int) (entry.getKey() - cursor));
					toPut.put(cursor, missing);
					result.add(missing);
				}
				// No need to truncate, as we're just counting a read
				result.add(entry.getValue());
				cursor = endOf(entry);
			}
			if (end > cursor) {
				OptimizeRecord missing = new OptimizeRecord(cursor, (int) (end - cursor));
				toPut.put(cursor, missing);
				result.add(missing);
			}
			recs.putAll(toPut);
			assert !result.isEmpty();
			return result;
		}
	}

	// Optimization routines
	private static void examineVn(UniqueState state, VarnodeTpl vn, int i,
			int inslot, int secnum) {
		if (vn == null) {
			return;
		}
		if (!vn.getSpace().isUniqueSpace()) {
			return;
		}
		if (vn.getOffset().getType() != ConstTpl.const_type.real) {
			return;
		}

		long offset = vn.getOffset().getReal();
		int size = (int) vn.getSize().getReal();
		if (inslot >= 0) {
			for (OptimizeRecord rec : state.getDefinitions(offset, size)) {
				rec.updateRead(i, inslot, secnum);
			}
		}
		else {
			OptimizeRecord rec = new OptimizeRecord(offset, size);
			rec.updateWrite(i, secnum);
			state.set(offset, size, rec);
		}
	}

	private static boolean possibleIntersection(VarnodeTpl vn1, VarnodeTpl vn2) {
		// Conservatively test whether vn1 and vn2 can intersect
		if (vn1.getSpace().isConstSpace()) {
			return false;
		}
		if (vn2.getSpace().isConstSpace()) {
			return false;
		}

		boolean u1 = vn1.getSpace().isUniqueSpace();
		boolean u2 = vn2.getSpace().isUniqueSpace();

		if (u1 != u2) {
			return false;
		}

		if (vn1.getSpace().getType() != ConstTpl.const_type.spaceid) {
			return true;
		}
		if (vn2.getSpace().getType() != ConstTpl.const_type.spaceid) {
			return true;
		}
		AddrSpace spc = vn1.getSpace().getSpace();
		if (!spc.equals(vn2.getSpace().getSpace())) {
			return false;
		}

		if (vn2.getOffset().getType() != ConstTpl.const_type.real) {
			return true;
		}
		if (vn2.getSize().getType() != ConstTpl.const_type.real) {
			return true;
		}

		if (vn1.getOffset().getType() != ConstTpl.const_type.real) {
			return true;
		}
		if (vn1.getSize().getType() != ConstTpl.const_type.real) {
			return true;
		}

		long offset = vn1.getOffset().getReal();
		long size = vn1.getSize().getReal();

		long off = vn2.getOffset().getReal();
		if (off + vn2.getSize().getReal() - 1 < offset) {
			return false;
		}
		if (off > (offset + size - 1)) {
			return false;
		}
		return true;
	}

	// Does op potentially read vn
	// This is extremely conservative. Basically any op where
	// we can't see exactly what might be written is considered
	// interference
	private boolean readWriteInterference(VarnodeTpl vn, OpTpl op, boolean checkread) {
		switch (op.getOpcode()) {
			case CPUI_MULTIEQUAL:
			case CPUI_PTRSUB:
			case CPUI_INDIRECT:
			case CPUI_CAST:
			case CPUI_LOAD:
			case CPUI_STORE:
			case CPUI_BRANCH:
			case CPUI_CBRANCH:
			case CPUI_BRANCHIND:
			case CPUI_CALL:
			case CPUI_CALLIND:
			case CPUI_CALLOTHER:
			case CPUI_RETURN:
			case CPUI_PTRADD: // Another value might jump in here
				return true;
			default:
				break;
		}

		if (checkread) {
			int numinputs = op.numInput();
			for (int i = 0; i < numinputs; ++i) {
				if (possibleIntersection(vn, op.getIn(i))) {
					return true;
				}
			}
		}

		// We always check for writes to -vn-
		VarnodeTpl vn2 = op.getOut();
		if (vn2 != null) {
			if (possibleIntersection(vn, vn2)) {
				return true;
			}
		}
		return false;
	}

	// Look for reads and writes to temporaries
	private void optimizeGather1(Constructor ct, UniqueState state, int secnum) {
		ConstructTpl tpl;
		if (secnum < 0) {
			tpl = ct.getTempl();
		}
		else {
			tpl = ct.getNamedTempl(secnum);
		}
		if (tpl == null) {
			return;
		}
		VectorSTL<OpTpl> ops = tpl.getOpvec();
		for (int i = 0; i < ops.size(); ++i) {
			OpTpl op = ops.get(i);
			for (int j = 0; j < op.numInput(); ++j) {
				VarnodeTpl vnin = op.getIn(j);
				examineVn(state, vnin, i, j, secnum);
			}
			VarnodeTpl vn = op.getOut();
			examineVn(state, vn, i, -1, secnum);
		}
	}

	// Make sure any temp used by the export is not optimized away
	private void optimizeGather2(Constructor ct, UniqueState state, int secnum) {
		ConstructTpl tpl;
		if (secnum < 0) {
			tpl = ct.getTempl();
		}
		else {
			tpl = ct.getNamedTempl(secnum);
		}
		if (tpl == null) {
			return;
		}
		HandleTpl hand = tpl.getResult();
		if (hand == null) {
			return;
		}
		if (hand.getPtrSpace().isUniqueSpace()) {
			if (hand.getPtrOffset().getType() == ConstTpl.const_type.real) {
				long offset = hand.getPtrOffset().getReal();
				int size = (int) hand.getPtrSize().getReal();
				for (OptimizeRecord rec : state.getDefinitions(offset, size)) {
					rec.updateExport();
					// NOTE: Could this just be updateRead?
					// Technically, an exported handle could be written by the parent....
				}
			}
		}
		if (hand.getSpace().isUniqueSpace()) {
			if ((hand.getPtrSpace().getType() == ConstTpl.const_type.real) &&
				(hand.getPtrOffset().getType() == ConstTpl.const_type.real)) {
				long offset = hand.getPtrOffset().getReal();
				int size = (int) hand.getPtrSize().getReal();
				for (OptimizeRecord rec : state.getDefinitions(offset, size)) {
					rec.updateExport();
					// NOTE: Could this just be updateRead?
					// Technically, an exported handle could be written by the parent....
				}
			}
		}
	}

	private OptimizeRecord findValidRule(Constructor ct, UniqueState state) {
		for (Entry<Long, OptimizeRecord> ent : state.recs.entrySet()) {
			OptimizeRecord currec = ent.getValue();
			if ((currec.writecount == 1) && (currec.readcount == 1) &&
				(currec.readsection == currec.writesection)) {
				// Temporary must be read and written exactly once
				ConstructTpl tpl;
				if (currec.readsection < 0) {
					tpl = ct.getTempl();
				}
				else {
					tpl = ct.getNamedTempl(currec.readsection);
				}
				VectorSTL<OpTpl> ops = tpl.getOpvec();
				OpTpl writeop = ops.get(currec.writeop);
				OpTpl readop = ops.get(currec.readop);
				if (currec.writeop >= currec.readop) {
					throw new SleighError("Read of temporary before write", ct.location);
				}

				VarnodeTpl writevn = writeop.getOut();
				VarnodeTpl readvn = readop.getIn(currec.inslot);

				/**
				 * Because the record can change size and position, we have to check if the varnode
				 * "connecting" the write and read ops is actually the same varnode. If not, then we
				 * can't optimize it out.
				 * 
				 * There may be an opportunity here to re-write the size/offset when either the
				 * write or read op is a COPY, but I'll leave that for later discussion.
				 * 
				 * Actually, maybe not. If the truncation would be of a handle, we can't.
				 */
				if (!Objects.equals(writevn, readvn)) {
					continue;
				}

				if (readop.getOpcode() == OpCode.CPUI_COPY) {
					boolean saverecord = true;
					currec.opttype = 0;
					VarnodeTpl vn = readop.getOut();
					for (int i = currec.writeop + 1; i < currec.readop; ++i) {
						if (readWriteInterference(vn, ops.get(i), true)) {
							saverecord = false;
							break;
						}
					}
					if (saverecord) {
						return currec;
					}
				}
				if (writeop.getOpcode() == OpCode.CPUI_COPY) {
					boolean saverecord = true;
					currec.opttype = 1;
					VarnodeTpl vn = writeop.getIn(0);
					for (int i = currec.writeop + 1; i < currec.readop; ++i) {
						if (readWriteInterference(vn, ops.get(i), false)) {
							saverecord = false;
							break;
						}
					}
					if (saverecord) {
						return currec;
					}
				}
			}
		}
		return null;
	}

	private void applyOptimization(Constructor ct, OptimizeRecord rec) {
		VectorSTL<Integer> deleteops = new VectorSTL<>();
		ConstructTpl ctempl;
		if (rec.readsection < 0) {
			ctempl = ct.getTempl();
		}
		else {
			ctempl = ct.getNamedTempl(rec.readsection);
		}

		if (rec.opttype == 0) {
			int readop = rec.readop;
			OpTpl op = ctempl.getOpvec().get(readop);
			VarnodeTpl vnout = new VarnodeTpl(ct.location, op.getOut());
			ctempl.setOutput(vnout, rec.writeop);
			deleteops.push_back(readop);
		}
		else if (rec.opttype == 1) {
			int writeop = rec.writeop;
			OpTpl op = ctempl.getOpvec().get(writeop);
			VarnodeTpl vnin = new VarnodeTpl(ct.location, op.getIn(0));
			ctempl.setInput(vnin, rec.readop, rec.inslot);
			deleteops.push_back(writeop);
		}
		ctempl.deleteOps(deleteops);
	}

	private void checkUnusedTemps(Constructor ct, UniqueState state) {
		for (OptimizeRecord currec : state.recs.values()) {
			if (currec.readcount == 0) {
				if (printdeadwarning) {
					compiler.reportWarning(ct.location, "Temporary is written but not read");
				}
				writenoread += 1;
			}
			else if (currec.writecount == 0) {
				compiler.reportError(ct.location, "Temporary is read but not written");
				readnowrite += 1;
			}
		}
	}

	/**
	 * Checks {@code ct} to see whether p-code section contains an {@link OpTpl} which uses a
	 * varnode in the unique space which is larger than {@link SleighBase#MAX_UNIQUE_SIZE}.
	 * 
	 * @param ct constructor to check
	 * @param ctpl is the specific p-code section
	 */
	private void checkLargeTemporaries(Constructor ct, ConstructTpl ctpl) {
		VectorSTL<OpTpl> ops = ctpl.getOpvec();
		for (IteratorSTL<OpTpl> iter = ops.begin(); !iter.isEnd(); iter.increment()) {
			if (hasLargeTemporary(iter.get())) {
				if (printlargetempwarning) {
					compiler.reportWarning(ct.location,
						"Constructor uses temporary varnode larger than " +
							SleighBase.MAX_UNIQUE_SIZE + " bytes.");
				}
				largetemp++;
				return;
			}
		}
	}
	
	/**
	 * Checks {@code ct} to see whether exports a constant integer larger than the export size.
	 * @param ct constructor to check
	 * @param ctpl is the specific p-code section
	 */
	private void checkLargeIntegers(Constructor ct, ConstructTpl ctpl) {
		HandleTpl result = ctpl.getResult();
		if (result != null && result.getSpace().isConstSpace() && result.getSize().getType() == const_type.real && result.getPtrOffset().getType() == const_type.real) {
			long bytes = result.getSize().getReal();
			long value = result.getPtrOffset().getReal();
			long bytes_min;
			if (value < 0) {
				bytes_min = (Long.SIZE - Long.numberOfLeadingZeros(~value) + 2 + 7) / 8;
			} else {
				bytes_min = (Long.SIZE - Long.numberOfLeadingZeros(value) + 7) / 8;
			}
			if (bytes < bytes_min) {
				largeint++;
				if (printlargeintwarning) {
					compiler.reportWarning(ct.location,
							"Constructor export a constant of " + bytes + " bytes, but it's value require " + bytes_min + " to not be truncated.");
				}
			}
		}
	}

	private void optimize(Constructor ct) {
		OptimizeRecord currec;
		UniqueState state = new UniqueState();
		int numsections = ct.getNumSections();
		do {
			state.clear();
			for (int i = -1; i < numsections; ++i) {
				optimizeGather1(ct, state, i);
				optimizeGather2(ct, state, i);
			}
			currec = findValidRule(ct, state);
			if (currec != null) {
				applyOptimization(ct, currec);
			}
		}
		while (currec != null);
		checkUnusedTemps(ct, state);
	}

	public ConsistencyChecker(SleighCompile cp, SubtableSymbol rt, boolean unnecessary,
			boolean warndead, boolean warnlargetemp) {
		compiler = cp;
		root_symbol = rt;
		unnecessarypcode = 0;
		readnowrite = 0;
		writenoread = 0;
		//number of constructors which reference a temporary varnode larger than SleighBase.MAX_UNIQUE_SIZE
		largetemp = 0;
		largeint = 0;
		printextwarning = unnecessary;
		printdeadwarning = warndead;
		//whether to print information about constructors which reference large temporary varnodes
		printlargetempwarning = warnlargetemp;
		printlargeintwarning = true;
	}

	// Main entry point for size consistency check
	public boolean testSizeRestrictions() {
		setPostOrder(root_symbol);
		boolean testresult = true;

		for (int i = 0; i < postorder.size(); ++i) {
			SubtableSymbol sym = postorder.get(i);
			if (!checkSubtable(sym)) {
				testresult = false;
			}
		}
		return testresult;
	}

	public boolean testTruncations() {
		// Now that the sizemap is calculated, we can check/adjust the offset_plus templates
		boolean testresult = true;
		boolean isbigendian = compiler.isBigEndian();
		for (int i = 0; i < postorder.size(); ++i) {
			SubtableSymbol sym = postorder.get(i);
			int numconstruct = sym.getNumConstructors();
			Constructor ct;
			for (int j = 0; j < numconstruct; ++j) {
				ct = sym.getConstructor(j);

				int numsections = ct.getNumSections();
				for (int k = -1; k < numsections; ++k) {
					ConstructTpl tpl;
					if (k < 0) {
						tpl = ct.getTempl();
					}
					else {
						tpl = ct.getNamedTempl(k);
					}
					if (tpl == null) {
						continue;
					}
					if (!checkSectionTruncations(ct, tpl, isbigendian)) {
						testresult = false;
					}
				}
			}
		}
		return testresult;
	}
	
	public void testLargeIntegers() {
		for (int i = 0; i < postorder.size(); ++i) {
			SubtableSymbol sym = postorder.get(i);
			int numconstruct = sym.getNumConstructors();
			Constructor ct;
			for (int j = 0; j < numconstruct; ++j) {
				ct = sym.getConstructor(j);
				int numsections = ct.getNumSections();
				for (int k = -1; k < numsections; ++k) {
					ConstructTpl tpl;
					if (k < 0) {
						tpl = ct.getTempl();
					}
					else {
						tpl = ct.getNamedTempl(k);
					}
					if (tpl == null) {
						continue;
					}
					checkLargeIntegers(ct, tpl);
				}
			}
		}
	}

	public void testLargeTemporary() {
		for (int i = 0; i < postorder.size(); ++i) {
			SubtableSymbol sym = postorder.get(i);
			int numconstruct = sym.getNumConstructors();
			Constructor ct;
			for (int j = 0; j < numconstruct; ++j) {
				ct = sym.getConstructor(j);

				int numsections = ct.getNumSections();
				for (int k = -1; k < numsections; ++k) {
					ConstructTpl tpl;
					if (k < 0) {
						tpl = ct.getTempl();
					}
					else {
						tpl = ct.getNamedTempl(k);
					}
					if (tpl == null) {
						continue;
					}
					checkLargeTemporaries(ct, tpl);
				}
			}
		}
	}

	public void optimizeAll() {
		for (int i = 0; i < postorder.size(); ++i) {
			SubtableSymbol sym = postorder.get(i);
			int numconstruct = sym.getNumConstructors();
			Constructor ct;
			for (int j = 0; j < numconstruct; ++j) {
				ct = sym.getConstructor(j);
				optimize(ct);
			}
		}
	}

	public int getNumUnnecessaryPcode() {
		return unnecessarypcode;
	}

	public int getNumReadNoWrite() {
		return readnowrite;
	}

	public int getNumWriteNoRead() {
		return writenoread;
	}

	/**
	 * Returns the number of constructors which reference a varnode in the unique space with size
	 * larger than {@link SleighBase#MAX_UNIQUE_SIZE}.
	 * 
	 * @return num constructors with large temp varnodes
	 */
	public int getNumLargeTemporaries() {
		return largetemp;
	}
	
	public int getNumLargeIntegers() {
		return largeint;
	}
}
