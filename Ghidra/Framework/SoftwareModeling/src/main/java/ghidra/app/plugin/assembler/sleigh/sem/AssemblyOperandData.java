/* ###
 * IP: GHIDRA
 **/
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package ghidra.app.plugin.assembler.sleigh.sem;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseBranch;
import ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseNumericToken;
import ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseToken;
import ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseTreeNode;

import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;

/**
 * Holds data about operands and suboperands from the assembler that Ghidra does
 * not currently provide. Most importantly, this class allows users to access
 * mask and value information about suboperands (Ghidra provides the masks and
 * values for top-level operands only).
 * <p>
 * Note, what is referred to as "suboperands" here is what Ghidra seems to refer
 * as "subtable operands".
 * <p>
 * An instance of this class is a node in a tree of AssemblyOperandData. For
 * example, the instruction
 * <code>MOV RAX, qword ptr [ R10 + R12 * 2 + 1 ]</code>, we have the tree:
 * <p>
 * <code>
 *              instruction
 *       ____________|____________________
 *       |                               |
 *     Reg64                           rm64
 *       |                               |
 *  reg64_x (RAX)                       Mem
 *                      _________________|___________
 *                      |                           |
 *                   segWide                      addr64
 *                            ______________________|_____________________
 *                            |               |               |          |
 *                         Base64          Index64          ss (2)   simm32_64
 *                            |               |                          |
 *                      base64_x (R10)  index64_x (R12)         simm32_64:simm32 (1)
 * </code>
 * <p>
 * Each node (which is labeled with the code name) represents a node in the
 * AssemblyOperandData tree.
 */
public class AssemblyOperandData {
	/**
	 * The wildcard symbol; e.g. Q1.
	 */
	private String wildcardName;

	/**
	 * The zero-based index of the wildcard in the assembly instruction. For
	 * example, in <code>MOV Q1, Q2</code>, <code>Q1</code> receives an index of 0,
	 * and <code>Q2</code> receives an index of 1.
	 */
	private int wildcardIdx;

	/**
	 * The operand type, as defined by OperandType. It is saved as an
	 * <code>int</code> here, but the OperandType class can be used to retrieve the
	 * type the integer represents.
	 */
	private int operandType;

	/**
	 * e.g. EAX
	 */
	private String operandName;

	/**
	 * The name that the assembler uses to represent a branch, e.g. index64.
	 */
	private String codeName;

	/**
	 * The mask of the (sub)operand.
	 */
	private byte[] mask;

	/**
	 * The value of the (sub)operand.
	 */
	private byte[] val;

	/**
	 * The number of leading bytes that should be added to the mask and value.
	 */
	private int byteShift;

	/**
	 * The expression that helps in shifting (in some cases) and is useful in
	 * determining where labels are located in jump instructions.
	 */
	private PatternExpression expression;

	/**
	 * The child nodes, which contain (sub)operands.
	 */
	private final List<AssemblyOperandData> children;

	/**
	 * Used to find operand data for backfills, since code name (which is what is
	 * usually used) is not available.
	 */
	private String description;

	/**
	 * True if this operand was assembled via backfill; false otherwise
	 */
	private boolean isBackfill;

	/**
	 * AssemblyOperandData constructor.
	 *
	 * @param wildcardName operand variable name
	 * @param wildcardIdx  operand index in the instruction
	 * @param operandType  see <a href=
	 *                     "https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/OperandType.html">...</a>
	 */
	public AssemblyOperandData(String wildcardName, int wildcardIdx, int operandType) {
		this.wildcardName = wildcardName;
		this.wildcardIdx = wildcardIdx;
		this.operandType = operandType;
		this.byteShift = 0;
		this.children = new ArrayList<>();
		this.isBackfill = false;
	}

	public AssemblyOperandData() {
		this.children = new ArrayList<>();
		this.isBackfill = false;
	}

	/**
	 * Build the operand data tree that will contain the suboperand info and be
	 * returned to the user as a field of each {@code AssemblyResolution} object.
	 * <p>
	 * The substitutions of the parse tree gives a hierarchy of the suboperands.
	 * This hierarchy is used for this operand data tree. A pointer to this tree
	 * will exist in every {@code AssemblyResolution} object, allowing the entire
	 * tree to be accessed from each operand of each result.
	 * 
	 * @param node pass in the root node of the parse tree
	 * @return skeleton of an operand data tree
	 */
	protected static AssemblyOperandData buildAssemblyOperandDataTree(AssemblyParseTreeNode node) {
		if (node instanceof AssemblyParseBranch) {
			// branch of the tree that contains one or more sub(operands)
			AssemblyOperandData operandData = new AssemblyOperandData();
			AssemblyParseBranch tree = (AssemblyParseBranch) node;
			// code name is how we find the node we want in this tree
			operandData.setCodeName(tree.getProduction().getLHS().getName());
			for (AssemblyParseTreeNode token : tree.getSubstitutions()) {
				AssemblyOperandData childOperandData = buildAssemblyOperandDataTree(token);
				if (childOperandData != null) {
					operandData.addChild(childOperandData);
				}
			}
			return operandData;
		} else if (node instanceof AssemblyParseNumericToken
				|| (node instanceof AssemblyParseToken && node.getOperandData() != null)) {
			// leaf of the tree - consists of a sub(operand)
			AssemblyOperandData operandData = new AssemblyOperandData();
			AssemblyParseToken token = (AssemblyParseToken) node;

			// fill in some fields of the AssemblyOperandData that will be returned in the
			// results to the user
			operandData.setCodeName(token.getSym().getName());
			operandData.setOperandName(token.generateString());
			AssemblyOperandData operandDataTarget = token.getOperandData();
			if (operandDataTarget != null) {
				operandData.setWildcardName(operandDataTarget.getWildcardName());
				operandData.setWildcardIdx(operandDataTarget.getWildcardIdx());
				operandData.setOperandType(operandDataTarget.getOperandType());
			}
			return operandData;
		}
		return null;
	}

	/**
	 * Get the variable name of the operand.
	 * 
	 * @return wildcard name
	 */
	public String getWildcardName() {
		return wildcardName;
	}

	/**
	 * Set the variable name of the operand.
	 * 
	 * @param wildcardName variable name (e.g. Q1)
	 */
	public void setWildcardName(String wildcardName) {
		this.wildcardName = wildcardName;
	}

	/**
	 * Get the index of the wildcard in the instruction.
	 * 
	 * @return wildcard index
	 */
	public int getWildcardIdx() {
		return wildcardIdx;
	}

	/**
	 * Set the index of the wildcard in the instruction.
	 * 
	 * @param wildcardIdx index
	 */
	public void setWildcardIdx(int wildcardIdx) {
		this.wildcardIdx = wildcardIdx;
	}

	/**
	 * Get the operand type. See <a href=
	 * "https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/OperandType.html">...</a>.
	 *
	 * @return operand type
	 */
	public int getOperandType() {
		return operandType;
	}

	/**
	 * Set the operand type.
	 *
	 * @param operandType the operand type, as defined by <a href=
	 *                    "https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/OperandType.html">...</a>
	 */
	public void setOperandType(int operandType) {
		this.operandType = operandType;
	}

	/**
	 * Get the name of the operand.
	 * 
	 * @return operand name
	 */
	public String getOperandName() {
		return operandName;
	}

	/**
	 * Set the operand name.
	 * 
	 * @param operandName operand name
	 */
	public void setOperandName(String operandName) {
		this.operandName = operandName;
	}

	/**
	 * Get the name from Ghidra's assembler that represents the branch that this
	 * operand is the root node of.
	 * 
	 * @return branch name
	 */
	public String getCodeName() {
		return codeName;
	}

	/**
	 * Set the branch name that this operand is the root node of.
	 * 
	 * @param codeName branch name
	 */
	public void setCodeName(String codeName) {
		this.codeName = codeName;
	}

	/**
	 * Get the mask of this sub(operand) within the instruction.
	 * 
	 * @return mask
	 */
	public byte[] getMask() {
		return mask;
	}

	/**
	 * Set the mask of this sub(operand).
	 * 
	 * @param mask mask
	 */
	public void setMask(byte[] mask) {
		this.mask = mask;
	}

	/**
	 * Get the value of this sub(operand) within the instruction.
	 * 
	 * @return value
	 */
	public byte[] getVal() {
		return val;
	}

	/**
	 * Set the value of this sub(operand).
	 * 
	 * @param val value
	 */
	public void setVal(byte[] val) {
		this.val = val;
	}

	/**
	 * Get the number of bytes the mask/value should be shifted within the
	 * instruction.
	 * 
	 * @return number of bytes to shift right
	 */
	public int getByteShift() {
		return byteShift;
	}

	/**
	 * Add to the number of bytes to shift the mask/value.
	 * 
	 * @param amt number of bytes to shift right
	 */
	public void addByteShift(int amt) {
		this.byteShift += amt;
	}

	/**
	 * Get the expression that defines the mask/value within a byte.
	 * 
	 * @return expression
	 */
	public PatternExpression getExpression() {
		return this.expression;
	}

	/**
	 * Set the expression.
	 * 
	 * @param e expression
	 */
	public void setExpression(PatternExpression e) {
		this.expression = e;
	}

	/**
	 * Get all child operands of this operand.
	 * 
	 * @return list of child operands
	 */
	public List<AssemblyOperandData> getChildren() {
		return children;
	}

	/**
	 * Add child operands of this operand.
	 * 
	 * @param operandData child operand
	 */
	public void addChild(AssemblyOperandData operandData) {
		this.children.add(operandData);
	}

	/**
	 * Set the description of this operand.
	 * 
	 * @param description description
	 */
	public void setDescription(String description) {
		this.description = description;
	}

	/**
	 * True if the operand was assembled via backfill; false otherwise.
	 */
	public void makeBackfill() {
		this.isBackfill = true;
	}

	/**
	 * Get only the operand data that contain wildcards.
	 * 
	 * @return list of operand data that contain wildcards
	 */
	public List<AssemblyOperandData> getWildcardOperandData() {
		return getWildcardOperandData(this);
	}

	/**
	 * Extract the AssemblyOperandData objects that are wildcarded.
	 * 
	 * @param operandData the AssemblyOperandData object to check if it should be
	 *                    returned
	 * @return a list of AssemblyOperandData nodes that are wildcarded
	 */
	private List<AssemblyOperandData> getWildcardOperandData(AssemblyOperandData operandData) {
		List<AssemblyOperandData> results = new ArrayList<>();
		if (operandData.wildcardName != null) {
			results.add(operandData);
		}
		for (AssemblyOperandData childOperandData : operandData.children) {
			results.addAll(childOperandData.getWildcardOperandData(childOperandData));
		}
		return results;
	}

	/**
	 * Given the code name, find the corresponding operand data node.
	 * 
	 * @param codename code name of the node to find
	 * @return operand data of the code name, null if node could not be found
	 */
	protected AssemblyOperandData findOperandData(String codename) {
		if (this.codeName.equals(codename)) {
			return this;
		}

		for (AssemblyOperandData operandData : children) {
			AssemblyOperandData result = operandData.findOperandData(codename);
			if (result != null) {
				return result;
			}
		}
		return null;
	}

	/**
	 * Give a description, find the corresponding operand data node.
	 * 
	 * @param descriptionToFind description of the node to find
	 * @return operand data of the description, null if node could not be found
	 */
	protected AssemblyOperandData findDescription(String descriptionToFind) {
		if (this.description != null && this.description.equals(descriptionToFind)) {
			return this;
		}

		for (AssemblyOperandData operandData : children) {
			AssemblyOperandData result = operandData.findDescription(descriptionToFind);
			if (result != null) {
				return result;
			}
		}
		return null;
	}

	/**
	 * Some operands don't have a mask and value (instead, these operands seem to
	 * influence bits in the opcode). These operands are AssemblyParseTokens instead
	 * of the usual AssemblyParseNumericToken, which means the assembler does not
	 * fill in the mask and value field of the AssemblyOperandData. To solve this
	 * problem, this method searches for wildcarded AssemblyOperandData that have
	 * null masks and values and fills it in with empty byte arrays.
	 * 
	 * @param totalBytes total number of bytes in the instruction, used to determine
	 *                   length of the empty byte array
	 */
	protected void fillMissingMasksVals(int totalBytes) {
		if (wildcardName != null && mask == null && val == null) {
			setMask(new byte[totalBytes]);
			setVal(new byte[totalBytes]);
		}
		for (AssemblyOperandData child : children) {
			child.fillMissingMasksVals(totalBytes);
		}
	}

	/**
	 * Add leading and trailing bytes to mask and value, so that they have the same
	 * number of bytes as the instruction.
	 * <p>
	 * When the mask and value of the sub(operand) is retrieved from the assembler,
	 * the leading and trailing bytes are not returned. Using the shifts that are
	 * provided by the assembler, the leading and trailing bytes are reassembled
	 * here.
	 * 
	 * @param totalBytes length of the instruction, in number of bytes
	 */
	protected void applyShifts(int totalBytes) {
		applyShifts(0, totalBytes);
	}

	/**
	 * Add leading and trailing bytes to mask and value.
	 * <p>
	 * |-------------------------totalBytes------------------------------|
	 * |---amt---|---current mask/val len---|---implied trailing bytes---|
	 * 
	 * @param amt        number of leading bytes to add
	 * @param totalBytes total number of bytes in the instruction
	 */
	private void applyShifts(int amt, int totalBytes) {
		amt += byteShift;
		// amt is the sum of this operand's shift and all the shifts in the levels
		// above.
		// byteShift in backfill operands already contain the sum of all the levels
		// above since backfills are shifted into place after the entire instruction is
		// put together.
		// using amt in a backfill would double count shifts.
		int shiftAmt = isBackfill ? byteShift : amt;
		if (mask != null && val != null && (shiftAmt > 0 || totalBytes > mask.length)) {
			// make new arrays that are as long as the instruction
			byte[] newMask = new byte[totalBytes];
			byte[] newVal = new byte[totalBytes];
			// find when the current mask/val would go in the new arrays and populate them
			for (int i = shiftAmt; i < mask.length + shiftAmt; i++) {
				try {
					newMask[i] = mask[i - shiftAmt];
					newVal[i] = val[i - shiftAmt];
				} catch (ArrayIndexOutOfBoundsException e) {
					throw new RuntimeException("Shifting failure:\n\tTotal instruction bytes (new mask/value length): "
							+ totalBytes + "\n\tCurrent mask/value length: " + mask.length + "\n\tShift amount: "
							+ shiftAmt
							+ "\nSum of current length and shift amount should be less than or equal to total bytes.\nAttempting to shift byte "
							+ (i - shiftAmt) + " of current mask/value into byte " + i + " of new mask/value.");
				}
			}

			this.mask = newMask;
			this.val = newVal;
		}

		for (AssemblyOperandData operandData : children) {
			operandData.applyShifts(amt, totalBytes);
		}
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("NAME: ").append(wildcardName);
		sb.append("\nOPNM: ").append(operandName);
		sb.append("\nCODE: ").append(codeName);
		if (expression == null) {
			sb.append("\nExpression: null");
		} else {
			sb.append("\nExpression: ").append(expression);
		}
		sb.append("\nSHMT: ").append(byteShift);
		if (mask == null) {
			sb.append("\nMASK: null");
		} else {
			sb.append("\nMASK: [");
			for (byte b : mask) {
				sb.append(b).append(", ");
			}
			sb.delete(sb.length() - 2, sb.length()).append(']');
		}
		if (val == null) {
			sb.append("\nVAL:  null");
		} else {
			sb.append("\nVAL:  [");
			for (byte b : val) {
				sb.append(b).append(", ");
			}
			sb.delete(sb.length() - 2, sb.length());
			sb.append(']');
		}
		return sb.toString();
	}

	/**
	 * Make a deep copy of this object.
	 * 
	 * @return a new copy of this AssemblyOperandData object
	 */
	public AssemblyOperandData copy() {
		AssemblyOperandData newOperandData = new AssemblyOperandData(wildcardName, wildcardIdx, operandType);
		newOperandData.setOperandName(operandName);
		newOperandData.setCodeName(codeName);
		newOperandData.setExpression(getExpression());
		newOperandData.addByteShift(getByteShift());
		newOperandData.setMask(getMask());
		newOperandData.setVal(getVal());
		newOperandData.setDescription(description);
		newOperandData.isBackfill = this.isBackfill;
		for (AssemblyOperandData child : children) {
			newOperandData.addChild(child.copy());
		}
		return newOperandData;
	}

}
