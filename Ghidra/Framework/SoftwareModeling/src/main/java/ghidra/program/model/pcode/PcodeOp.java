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
package ghidra.program.model.pcode;

import java.util.*;

import ghidra.program.model.address.*;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * 
 *
 * Pcode Op describes a generic machine operation.  You can think of
 * it as the microcode for a specific processor's instruction set.  There
 * are a finite number of PcodeOp's that theoretically can define the
 * operations for any given processor.
 * 
 * Pcode have
 *    An operation code
 *    Some number of input parameter varnodes
 *    possible output varnode
 * 
 */
public class PcodeOp {

	// The opcodes of the Pcode language

	// Each Pcode Op is given a unique identifying index here
	public static final int UNIMPLEMENTED = 0;		// Place holder for unimplemented instruction
	public static final int COPY = 1;		        // Copy one operand to another 
	public static final int LOAD = 2;		        // Dereference a pointer into specified space
	public static final int STORE = 3;		        // Store at a pointer into specified space

	public static final int BRANCH = 4;		// Always branch 
	public static final int CBRANCH = 5;		// Conditional branch 
	public static final int BRANCHIND = 6;		// An indirect branch (jumptable)

	public static final int CALL = 7;		        // A call with absolute address
	public static final int CALLIND = 8;		// An indirect call
	public static final int CALLOTHER = 9;     // Other unusual subroutine calling conventions
	public static final int RETURN = 10;		// A return from subroutine

	public static final int INT_EQUAL = 11;	        // Return TRUE if operand1 == operand2 
	public static final int INT_NOTEQUAL = 12;	        // Return TRUE if operand1 != operand2
	public static final int INT_SLESS = 13;         	// Return TRUE if signed op1 < signed op2
	public static final int INT_SLESSEQUAL = 14;	// Return TRUE if signed op1 <= signed op2
	public static final int INT_LESS = 15;		// Return TRUE if unsigned op1 < unsigned op2
	// Also indicates borrow on unsigned substraction
	public static final int INT_LESSEQUAL = 16;	// Return TRUE if unsigned op1 <= unsigned op2
	public static final int INT_ZEXT = 17;		// Zero extend operand 
	public static final int INT_SEXT = 18;		// Sign extend operand 
	public static final int INT_ADD = 19;		// Unsigned addition of operands of same size 
	public static final int INT_SUB = 20;		// Unsigned subtraction of operands of same size 
	public static final int INT_CARRY = 21;        	// TRUE if adding two operands has overflow (carry) 
	public static final int INT_SCARRY = 22;   	// TRUE if carry in signed addition of 2 ops 
	public static final int INT_SBORROW = 23;  	// TRUE if borrow in signed subtraction of 2 ops 
	public static final int INT_2COMP = 24;    	// Twos complement (for subtracting) of operand 
	public static final int INT_NEGATE = 25;
	public static final int INT_XOR = 26;		// Exclusive OR of two operands of same size 
	public static final int INT_AND = 27;
	public static final int INT_OR = 28;
	public static final int INT_LEFT = 29;		// Left shift 
	public static final int INT_RIGHT = 30;	        // Right shift zero fill 
	public static final int INT_SRIGHT = 31;        	// Signed right shift 
	public static final int INT_MULT = 32;		// Integer multiplication 
	public static final int INT_DIV = 33;		// Unsigned integer division
	public static final int INT_SDIV = 34;		// Signed integer division
	public static final int INT_REM = 35;		// Unsigned mod (remainder)
	public static final int INT_SREM = 36;		// Signed mod (remainder)

	public static final int BOOL_NEGATE = 37;  	// Boolean negate or not
	public static final int BOOL_XOR = 38;		// Boolean xor
	public static final int BOOL_AND = 39;		// Boolean and (&&)
	public static final int BOOL_OR = 40;		// Boolean or (||)

	// floating point instructions:  No floating point data format is specified here,
	// although the exact operation of these instructions obviously depends on the
	// format.  For simulation, a "mode" variable specifying the floating point format
	// will be necessary.
	public static final int FLOAT_EQUAL = 41;          // Return TRUE if operand1 == operand2    
	public static final int FLOAT_NOTEQUAL = 42;	// Return TRUE if operand1 != operand2    
	public static final int FLOAT_LESS = 43;   	// Return TRUE if op1 < op2 
	public static final int FLOAT_LESSEQUAL = 44;	// Return TRUE if op1 <= op2
	// Slot 45 is unused
	public static final int FLOAT_NAN = 46;	// Return TRUE if neither op1 is NaN 

	public static final int FLOAT_ADD = 47;            // float addition
	public static final int FLOAT_DIV = 48;            // float division
	public static final int FLOAT_MULT = 49;           // float multiplication
	public static final int FLOAT_SUB = 50;            // float subtraction
	public static final int FLOAT_NEG = 51;            // float negation
	public static final int FLOAT_ABS = 52;            // float absolute value
	public static final int FLOAT_SQRT = 53;           // float square root

	public static final int FLOAT_INT2FLOAT = 54;      // convert int type to float type
	public static final int FLOAT_FLOAT2FLOAT = 55;    // convert between float sizes
	public static final int FLOAT_TRUNC = 56;          // round towards zero
	public static final int FLOAT_CEIL = 57;           // round towards +infinity
	public static final int FLOAT_FLOOR = 58;          // round towards -infinity
	public static final int FLOAT_ROUND = 59;          // round towards nearest

	// Internal opcodes for simplification.  Not typically generated in direct
	// translation.
	public static final int MULTIEQUAL = 60;  // Output equal to one of inputs, depending on execution
	public static final int INDIRECT = 61;    // Output probably equals input, but may be indirectly affected
	public static final int PIECE = 62;       // Output is constructed from multiple peices
	public static final int SUBPIECE = 63;    // Output is a subpiece of input0, input1=offset into input0

	public static final int CAST = 64;        // Cast from one type to another
	public static final int PTRADD = 65;      // outptr = ptrbase,offset, (size multiplier)
	public static final int PTRSUB = 66;      // outptr = &(ptr->subfield)
	public static final int SEGMENTOP = 67;
	public static final int CPOOLREF = 68;
	public static final int NEW = 69;
	public static final int INSERT = 70;
	public static final int EXTRACT = 71;
	public static final int POPCOUNT = 72;

	public static final int PCODE_MAX = 73;

	private static Hashtable<String, Integer> opcodeTable;

	private int opcode;
	private SequenceNumber seqnum;
	private Varnode[] input;
	private Varnode output;

	/**
	 * Constructor - pcode part of sequence of pcodes, some number of inputs, output
	 * 
	 * @param sq place in sequence of pcode
	 * @param op pcode operation
	 * @param numinputs number of inputs to operation, actual inputs not defined yet.
	 * @param out output from operation
	 */
	public PcodeOp(SequenceNumber sq, int op, int numinputs, Varnode out) {
		opcode = op;
		seqnum = sq;
		input = new Varnode[numinputs];
		output = out;
	}

	/**
	 * Constructor - pcode part of sequence of pcodes, inputs, outputs
	 * 
	 * @param sq place in sequence of pcode
	 * @param op pcode operation
	 * @param in inputs to operation
	 * @param out output from operation
	 */
	public PcodeOp(SequenceNumber sq, int op, Varnode[] in, Varnode out) {
		opcode = op;
		seqnum = sq;
		input = in;
		output = out;
	}

	/**
	 * Constructor - inputs and outputs
	 * 
	 * @param a address pcode is attached to
	 * @param sequencenumber unique sequence number for the specified address.
	 * @param op pcode operation
	 * @param in inputs to operation
	 * @param out output from operation
	 */
	public PcodeOp(Address a, int sequencenumber, int op, Varnode[] in, Varnode out) {
		opcode = op;
		seqnum = new SequenceNumber(a, sequencenumber);
		input = in;
		output = out;
	}

	/**
	 * Constructor - no output
	 * 
	 * @param a address pcode is attached to
	 * @param sequencenumber id within a single address
	 * @param op operation pcode performs
	 * @param in inputs from pcode operation
	 */
	public PcodeOp(Address a, int sequencenumber, int op, Varnode[] in) {
		this(a, sequencenumber, op, in, null);
	}

	/**
	 * Constructor - no inputs, output
	 * 
	 * @param a address pcode is attached to
	 * @param sequencenumber id within a single address
	 * @param op pcode operation
	 */
	public PcodeOp(Address a, int sequencenumber, int op) {
		this(a, sequencenumber, op, new Varnode[0], null);
	}

	/**
	 * @return pcode operation code
	 */
	public final int getOpcode() {
		return opcode;
	}

	/**
	 * @return number of input varnodes
	 */
	public final int getNumInputs() {
		if (input == null) {
			return 0;
		}
		return input.length;
	}

	/**
	 * @return get input varnodes
	 */
	public final Varnode[] getInputs() {
		return input;
	}

	/**
	 * @param i the i'th input varnode
	 * @return the i'th input varnode
	 */
	public final Varnode getInput(int i) {
		if (i >= input.length || i < 0) {
			return null;
		}
		return input[i];
	}

	/**
	 * @return get output varnodes
	 */
	public final Varnode getOutput() {
		return output;
	}

	/**
	 * Assuming vn is an input to this op, return its input slot number
	 * @param vn is the input varnode
	 * @return the slot number
	 */
	public final int getSlot(Varnode vn) {
		int n = input.length;
		int i;
		for (i = 0; i < n; ++i) {
			if (input[i] == vn) {
				break;
			}
		}
		return i;
	}

	/**
	 * @return get the string representation for the pcode operation
	 */
	public final String getMnemonic() {
		return getMnemonic(opcode);
	}

	/**
	 * Check if the pcode has been determined to be a dead operation.
	 * 
	 * @return true if the pcode has been determined to have no effect in the context it is used
	 */
	public boolean isDead() {
		return false;
	}

	/**
	 * @return true if the pcode assigns a value to an output varnode
	 */
	public final boolean isAssignment() {
		return (output != null);
	}

	/**
	 * @return the sequence number this pcode is within some number of pcode
	 */
	public final SequenceNumber getSeqnum() {
		return seqnum;
	}

	public Iterator<PcodeOp> getBasicIter() {		// Not used by minimal PcodeOp
		return null;
	}

	public Iterator<Object> getInsertIter() {		// Not used by minimal PcodeOp
		return null;
	}

	/**
	 * @return the pcode basic block this pcode belongs to
	 */
	public PcodeBlockBasic getParent() {
		return null;
	}

	/**
	 * Set the pcode operation code
	 * 
	 * @param o pcode operation code
	 */
	public final void setOpcode(int o) {
		opcode = o;
	}

	/**
	 * Set/Replace an input varnode at the given slot.
	 * 
	 * @param vn varnode to replace
	 * @param slot index of input varnode to be replaced
	 */
	public final void setInput(Varnode vn, int slot) {
		if (input == null) {
			input = new Varnode[slot + 1];
			for (int i = 0; i < input.length; ++i) {
				input[i] = null;
			}
		}
		else if (slot >= input.length) {
			Varnode[] newinput = new Varnode[slot + 1];
			for (int i = 0; i < input.length; ++i) {
				newinput[i] = input[i];
			}
			for (int i = input.length; i < newinput.length; ++i) {
				newinput[i] = null;
			}
			input = newinput;
		}
		input[slot] = vn;
	}

	/**
	 * Remove a varnode at the given slot from the list of input varnodes
	 * 
	 * @param slot index of input varnode to remove
	 */
	public final void removeInput(int slot) {
		if (input.length == 1) {
			input = null;
			return;
		}
		Varnode[] newinput = new Varnode[input.length - 1];
		for (int i = 0; i < slot; ++i) {
			newinput[i] = input[i];
		}
		for (int i = slot; i < newinput.length; ++i) {
			newinput[i] = input[i + 1];
		}
		input = newinput;
	}

	/**
	 * Insert an input varnode at the given index of input varnodes
	 * 
	 * @param vn varnode to insert
	 * @param slot insert index in input varnode list
	 */
	public final void insertInput(Varnode vn, int slot) {
		if (input == null) {
			setInput(vn, slot);
			return;
		}
		Varnode[] newinput = new Varnode[input.length + 1];
		for (int i = 0; i < slot; ++i) {
			newinput[i] = input[i];
		}
		for (int i = slot + 1; i < newinput.length; ++i) {
			newinput[i] = input[i - 1];
		}
		newinput[slot] = vn;
		input = newinput;
	}

	/**
	 * Set a unique number for pcode ops that are attached to the same address
	 * 
	 * @param t unique id
	 */
	public final void setTime(int t) {
		seqnum.setTime(t);
	}

	/**
	 * Set relative position information of PcodeOps within
	 * a basic block, may change as basic block is edited.
	 * 
	 * @param ord relative position of pcode op in basic block
	 */
	public final void setOrder(int ord) {
		seqnum.setOrder(ord);
	}

	/**
	 * Set the output varnode for the pcode operation.
	 * 
	 * @param vn new output varnode
	 */
	public final void setOutput(Varnode vn) {
		output = vn;
	}

	public void buildXML(StringBuilder resBuf,AddressFactory addrFactory) {
		resBuf.append("<op");
		SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "code", opcode);
		resBuf.append('>');
		resBuf.append(seqnum.buildXML());
		if (output == null) {
			resBuf.append("<void/>");
		}
		else {
			output.buildXML(resBuf);
		}
		if ((opcode == PcodeOp.LOAD) || (opcode == PcodeOp.STORE)) {
			int spaceId = (int) input[0].getOffset();
			resBuf.append("<spaceid");
			AddressSpace space = addrFactory.getAddressSpace(spaceId);
			SpecXmlUtils.encodeStringAttribute(resBuf, "name", space.getName());
			resBuf.append("/>");
		}
		else if (input.length > 0) {
			input[0].buildXML(resBuf);
		}
		for (int i = 1; i < input.length; ++i) {
			input[i].buildXML(resBuf);
		}
		resBuf.append("</op>");
	}

	/**
	 * Read p-code from XML stream
	 * 
	 * @param parser is the XML stream
	 * @param pfact factory used to create p-code correctly
	 * 
	 * @return new PcodeOp
	 * @throws PcodeXMLException if XML layout is incorrect
	 */
	public static PcodeOp readXML(XmlPullParser parser, PcodeFactory pfact)
			throws PcodeXMLException {
		XmlElement el = parser.start("op");
		int opc = SpecXmlUtils.decodeInt(el.getAttribute("code"));
		if (!parser.peek().isStart()) {
			throw new PcodeXMLException("Missing <seqnum> in PcodeOp");
		}
		SequenceNumber seqnum = SequenceNumber.readXML(parser, pfact.getAddressFactory());
		if (!parser.peek().isStart()) {
			throw new PcodeXMLException("Missing output in PcodeOp");
		}
		Varnode output = Varnode.readXML(parser, pfact);
		ArrayList<Varnode> inputlist = new ArrayList<Varnode>();
		while (parser.peek().isStart()) {
			Varnode vn = Varnode.readXML(parser, pfact);
			inputlist.add(vn);
		}
		PcodeOp res;
		try {
			res = pfact.newOp(seqnum, opc, inputlist, output);
		}
		catch (UnknownInstructionException e) {
			throw new PcodeXMLException("Bad opcode: " + e.getMessage(), e);
		}
		parser.end(el);
		return res;
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		String s;
		if (output != null) {
			s = output.toString();
		}
		else {
			s = " --- ";
		}
		s += " " + getMnemonic() + " ";
		for (int i = 0; i < input.length; i++) {
			if (input[i] == null) {
				s += "null";
			}
			else {
				s += input[i].toString();
			}

			if (i < input.length - 1) {
				s += " , ";
			}
		}
		return s;
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		return opcode + seqnum.hashCode();
	}

	/**
	 * Generate a lookup table that maps pcode mnemonic strings to pcode operation codes.
	 */
	private static void generateOpcodeTable() {
		opcodeTable = new Hashtable<String, Integer>();
		for (int i = 0; i < PCODE_MAX; i++) {
			opcodeTable.put(getMnemonic(i), i);
		}
		// Put in Pcode template directives
		opcodeTable.put("BUILD", MULTIEQUAL);
		opcodeTable.put("DELAY_SLOT", INDIRECT);
		opcodeTable.put("LABEL", PTRADD);
		opcodeTable.put("CROSSBUILD", PTRSUB);
	}

	/**
	 * Get string representation for p-code operation
	 * 
	 * @param op operation code
	 * @return String representation of p-code operation
	 */
	public final static String getMnemonic(int op) {
		switch (op) {
			case UNIMPLEMENTED:
				return "UNIMPLEMENTED";
			case COPY:
				return "COPY";
			case LOAD:
				return "LOAD";
			case STORE:
				return "STORE";
			case BRANCH:
				return "BRANCH";
			case CBRANCH:
				return "CBRANCH";
			case BRANCHIND:
				return "BRANCHIND";
			case CALL:
				return "CALL";
			case CALLIND:
				return "CALLIND";
			case CALLOTHER:
				return "CALLOTHER";
			case RETURN:
				return "RETURN";

			case INT_EQUAL:
				return "INT_EQUAL";
			case INT_NOTEQUAL:
				return "INT_NOTEQUAL";
			case INT_SLESS:
				return "INT_SLESS";
			case INT_SLESSEQUAL:
				return "INT_SLESSEQUAL";
			case INT_LESS:
				return "INT_LESS";
			case INT_LESSEQUAL:
				return "INT_LESSEQUAL";

			case INT_ZEXT:
				return "INT_ZEXT";
			case INT_SEXT:
				return "INT_SEXT";
			case INT_ADD:
				return "INT_ADD";
			case INT_SUB:
				return "INT_SUB";
			case INT_CARRY:
				return "INT_CARRY";
			case INT_SCARRY:
				return "INT_SCARRY";
			case INT_SBORROW:
				return "INT_SBORROW";
			case INT_2COMP:
				return "INT_2COMP";
			case INT_NEGATE:
				return "INT_NEGATE";
			case INT_XOR:
				return "INT_XOR";
			case INT_AND:
				return "INT_AND";
			case INT_OR:
				return "INT_OR";
			case INT_LEFT:
				return "INT_LEFT";
			case INT_RIGHT:
				return "INT_RIGHT";
			case INT_SRIGHT:
				return "INT_SRIGHT";
			case INT_MULT:
				return "INT_MULT";
			case INT_DIV:
				return "INT_DIV";
			case INT_SDIV:
				return "INT_SDIV";
			case INT_REM:
				return "INT_REM";
			case INT_SREM:
				return "INT_SREM";

			case BOOL_NEGATE:
				return "BOOL_NEGATE";
			case BOOL_XOR:
				return "BOOL_XOR";
			case BOOL_AND:
				return "BOOL_AND";
			case BOOL_OR:
				return "BOOL_OR";

			case FLOAT_EQUAL:
				return "FLOAT_EQUAL";
			case FLOAT_NOTEQUAL:
				return "FLOAT_NOTEQUAL";
			case FLOAT_LESS:
				return "FLOAT_LESS";
			case FLOAT_LESSEQUAL:
				return "FLOAT_LESSEQUAL";
			case FLOAT_NAN:
				return "FLOAT_NAN";
			case FLOAT_ADD:
				return "FLOAT_ADD";
			case FLOAT_DIV:
				return "FLOAT_DIV";
			case FLOAT_MULT:
				return "FLOAT_MULT";
			case FLOAT_SUB:
				return "FLOAT_SUB";
			case FLOAT_NEG:
				return "FLOAT_NEG";
			case FLOAT_ABS:
				return "FLOAT_ABS";
			case FLOAT_SQRT:
				return "FLOAT_SQRT";

			case FLOAT_INT2FLOAT:
				return "INT2FLOAT";
			case FLOAT_FLOAT2FLOAT:
				return "FLOAT2FLOAT";
			case FLOAT_TRUNC:
				return "TRUNC";
			case FLOAT_CEIL:
				return "CEIL";
			case FLOAT_FLOOR:
				return "FLOOR";
			case FLOAT_ROUND:
				return "ROUND";

			case MULTIEQUAL:
				return "MULTIEQUAL";
			case INDIRECT:
				return "INDIRECT";
			case PIECE:
				return "PIECE";
			case SUBPIECE:
				return "SUBPIECE";

			case CAST:
				return "CAST";
			case PTRADD:
				return "PTRADD";
			case PTRSUB:
				return "PTRSUB";
			case CPOOLREF:
				return "CPOOLREF";
			case NEW:
				return "NEW";
			case INSERT:
				return "INSERT";
			case EXTRACT:
				return "EXTRACT";
			case POPCOUNT:
				return "POPCOUNT";

			default:
				return "INVALID_OP";
		}
	}

	/**
	 * Get the p-code op code for the given mnemonic string.
	 * @param s is the mnemonic string
	 * @return the op code
	 * 
	 * @throws UnknownInstructionException if there is no matching mnemonic
	 */
	public static int getOpcode(String s) throws UnknownInstructionException {
		if (opcodeTable == null) {
			generateOpcodeTable();
		}
		Integer i = opcodeTable.get(s);
		if (i == null) {
			throw new UnknownInstructionException();
		}
		return i.intValue();
	}
}
