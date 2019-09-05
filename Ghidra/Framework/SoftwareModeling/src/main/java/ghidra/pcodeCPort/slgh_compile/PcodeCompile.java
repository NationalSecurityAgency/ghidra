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

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import generic.stl.IteratorSTL;
import generic.stl.VectorSTL;
import ghidra.pcode.utils.MessageFormattingUtils;
import ghidra.pcodeCPort.context.SleighError;
import ghidra.pcodeCPort.opcodes.OpCode;
import ghidra.pcodeCPort.semantics.*;
import ghidra.pcodeCPort.semantics.ConstTpl.const_type;
import ghidra.pcodeCPort.semantics.ConstTpl.v_field;
import ghidra.pcodeCPort.slghsymbol.*;
import ghidra.pcodeCPort.space.AddrSpace;
import ghidra.sleigh.grammar.Location;

public abstract class PcodeCompile {

	public final static Logger log = LogManager.getLogger(PcodeCompile.class);

	public VectorSTL<String> noplist = new VectorSTL<String>();
	private int local_labelcount;

	private int errors;
	private int warnings;
	private boolean enforceLocalKey = false;

	public void setEnforceLocalKey(boolean val) {
		enforceLocalKey = val;
	}

	public PcodeCompile() {
	}

	public abstract AddrSpace getDefaultSpace();

	public abstract AddrSpace getConstantSpace();

	public abstract AddrSpace getUniqueSpace();

	public abstract long allocateTemp();

	public abstract void addSymbol(SleighSymbol sym);

	public abstract SleighSymbol findSymbol(String nm);

	public abstract SectionSymbol newSectionSymbol(Location where, String text);

	public abstract VectorSTL<OpTpl> createCrossBuild(Location find, VarnodeTpl v,
			SectionSymbol second);

	public abstract SectionVector standaloneSection(ConstructTpl c);

	public abstract SectionVector firstNamedSection(ConstructTpl main, SectionSymbol sym);

	public abstract SectionVector nextNamedSection(SectionVector vec, ConstructTpl section,
			SectionSymbol sym);

	public abstract SectionVector finalNamedSection(SectionVector vec, ConstructTpl section);

	/**
	 * Handle a sleigh 'macro' invocation, returning the resulting p-code op templates (OpTpl)
	 * @param location is the file/line where the macro is invoked
	 * @param sym MacroSymbol is the macro symbol
	 * @param param is the parsed list of operand expressions
	 * @return a list of p-code op templates
	 */
	public abstract VectorSTL<OpTpl> createMacroUse(Location location, MacroSymbol sym,
			VectorSTL<ExprTree> param);

	public abstract void recordNop(Location location);

	public void reportError(Location location, String msg) {
		entry("reportError", location, msg);

		log.error(MessageFormattingUtils.format(location, msg));

		++errors;
	}

	public int getErrors() {
		return errors;
	}

	public void reportWarning(Location location, String msg) {
		entry("reportWarning", location, msg);

		log.warn(MessageFormattingUtils.format(location, msg));

		++warnings;
	}

	public int getWarnings() {
		return warnings;
	}

	public void resetLabelCount() {
		local_labelcount = 0;
	}

	private void force_size(VarnodeTpl vt, ConstTpl size, VectorSTL<OpTpl> ops)

	{
//        entry("force_size", vt, size, ops);
		if ((vt.getSize().getType() != ConstTpl.const_type.real) || (vt.getSize().getReal() != 0)) {
			return; // Size already exists
		}

		vt.setSize(size);
		if (!vt.isLocalTemp()) {
			return;
		}
		// If the variable is a local temporary
		// The size may need to be propagated to the various
		// uses of the variable
		OpTpl op;
		VarnodeTpl vn;

		for (int i = 0; i < ops.size(); ++i) {
			op = ops.get(i);
			vn = op.getOut();
			if ((vn != null) && (vn.isLocalTemp())) {
				if (vn.getOffset().equals(vt.getOffset())) {
					if ((size.getType() == ConstTpl.const_type.real) &&
						(vn.getSize().getType() == ConstTpl.const_type.real) &&
						(vn.getSize().getReal() != 0) && (vn.getSize().getReal() != size.getReal())) {
						throw new SleighError(String.format("Localtemp size mismatch: %d vs %d",
							vn.getSize().getReal(), size.getReal()), op.location);
					}
					vn.setSize(size);
				}
			}
			for (int j = 0; j < op.numInput(); ++j) {
				vn = op.getIn(j);
				if (vn.isLocalTemp() && (vn.getOffset().equals(vt.getOffset()))) {
					if ((size.getType() == ConstTpl.const_type.real) &&
						(vn.getSize().getType() == ConstTpl.const_type.real) &&
						(vn.getSize().getReal() != 0) && (vn.getSize().getReal() != size.getReal())) {
						throw new SleighError(String.format("Input size mismatch: %d vs %d",
							vn.getSize().getReal(), size.getReal()), op.location);
					}
					vn.setSize(size);
				}
			}
		}
	}

	// Build temporary variable (with zerosize)
	public VarnodeTpl buildTemporary(Location location) {
		entry("buildTemporary", location);
		VarnodeTpl res =
			new VarnodeTpl(location, new ConstTpl(getUniqueSpace()), new ConstTpl(
				ConstTpl.const_type.real, allocateTemp()),
				new ConstTpl(ConstTpl.const_type.real, 0));
		res.setUnnamed(true);
		return res;
	}

	// Create a label symbol
	public LabelSymbol defineLabel(Location location, String name) {
		entry("defineLabel", location, name);
		LabelSymbol labsym = new LabelSymbol(location, name, local_labelcount++);
		addSymbol(labsym); // Add symbol to local scope
		return labsym;
	}

	// Create placeholder OpTpl for a label
	public VectorSTL<OpTpl> placeLabel(Location location, LabelSymbol labsym) {
		entry("placeLabel", location, labsym);
		if (labsym.isPlaced()) {
			reportError(labsym.getLocation(),
				String.format("Label '%s' is placed more than once", labsym.getName()));
		}
		labsym.setPlaced();
		VectorSTL<OpTpl> res = new VectorSTL<OpTpl>();
		OpTpl op = new OpTpl(location, OpCode.CPUI_PTRADD);
		VarnodeTpl idvn =
			new VarnodeTpl(location, new ConstTpl(getConstantSpace()), new ConstTpl(
				ConstTpl.const_type.real, labsym.getIndex()), new ConstTpl(
				ConstTpl.const_type.real, 4));
		op.addInput(idvn);
		res.push_back(op);
		return res;
	}

	// Set constructors handle to indicate given varnode
	public ConstructTpl setResultVarnode(ConstructTpl ct, VarnodeTpl vn) {
		entry("setResultVarnode", ct, vn);
		HandleTpl res = new HandleTpl(vn);
		ct.setResult(res);
		return ct;
	}

	// Set constructors handle to be the value pointed
	// at by -vn-
	public ConstructTpl setResultStarVarnode(ConstructTpl ct, StarQuality star, VarnodeTpl vn) {
		entry("setResultStarVarnode", ct, star, vn);
		HandleTpl res =
			new HandleTpl(star.getId(), new ConstTpl(ConstTpl.const_type.real, star.getSize()), vn,
				getUniqueSpace(), allocateTemp());
		ct.setResult(res);
		return ct;
	}

	public void newLocalDefinition(Location location, String varname) {
		entry("newLocalDefinition", location, varname);
		newLocalDefinition(location, varname, 0);
	}

	public void newLocalDefinition(Location location, String varname, int size) {
		entry("newLocalDefinition", location, varname, size);

		// Create a new temporary symbol (without generating any pcode)
		VarnodeSymbol sym;
		VarnodeTpl tmpvn = buildTemporary(location);
		if (size != 0) {
			tmpvn.setSize(new ConstTpl(ConstTpl.const_type.real, size)); // Size was explicitly specified
		}
		sym =
			new VarnodeSymbol(location, varname, tmpvn.getSpace().getSpace(),
				tmpvn.getOffset().getReal(), (int) tmpvn.getSize().getReal());
		addSymbol(sym);
	}

	public VectorSTL<OpTpl> newOutput(Location location, boolean usesLocalKey, ExprTree rhs,
			String varname) {
		entry("newOutput", location, rhs, varname);
		return newOutput(location, usesLocalKey, rhs, varname, 0);
	}

	public VectorSTL<OpTpl> newOutput(Location location, boolean usesLocalKey, ExprTree rhs,
			String varname, int size) {
		entry("newOutput", location, rhs, varname, size);
		VarnodeSymbol sym;
		VarnodeTpl tmpvn = buildTemporary(location);
		if (size != 0) {
			tmpvn.setSize(new ConstTpl(ConstTpl.const_type.real, size)); // Size
		}
		else if ((rhs.getSize().getType() == ConstTpl.const_type.real) &&
			(rhs.getSize().getReal() != 0)) {
			tmpvn.setSize(rhs.getSize()); // Inherit size from unnamed
		}
		// expression result
		// Only inherit if the size is real, otherwise we
		// cannot build the VarnodeSymbol with a placeholder constant
		rhs.setOutput(location, tmpvn);
		// Create new symbol regardless
		sym =
			new VarnodeSymbol(location, varname, tmpvn.getSpace().getSpace(),
				tmpvn.getOffset().getReal(), (int) tmpvn.getSize().getReal());
		addSymbol(sym);
		if ((!usesLocalKey) && enforceLocalKey) {
			reportError(location, "Must use 'local' keyword to define symbol '" + varname + "'");
		}
		return ExprTree.toVector(rhs);
	}

	// Create new expression with output -outvn-
	// built by performing -opc- on input vn.
	// Free input expression
	public ExprTree createOp(Location location, OpCode opc, ExprTree vn) {
		entry("createOp", location, opc, vn);
		VarnodeTpl outvn = buildTemporary(location);
		OpTpl op = new OpTpl(location, opc);
		op.addInput(vn.outvn);
		op.setOutput(outvn);
		vn.ops.push_back(op);
		vn.outvn = new VarnodeTpl(location, outvn);
		return vn;
	}

	// Create new expression with output -outvn-
	// built by performing -opc- on inputs vn1 and vn2.
	// Free input expressions
	public ExprTree createOp(Location location, OpCode opc, ExprTree vn1, ExprTree vn2) {
		entry("createOp", location, opc, vn1, vn2);
		VarnodeTpl outvn = buildTemporary(location);
		vn1.ops.appendAll(vn2.ops);
		vn2.ops.clear();
		OpTpl op = new OpTpl(location, opc);
		op.addInput(vn1.outvn);
		op.addInput(vn2.outvn);
		vn2.outvn = null;
		op.setOutput(outvn);
		vn1.ops.push_back(op);
		vn1.outvn = new VarnodeTpl(location, outvn);
		return vn1;
	}

	// Create an op with explicit output and two inputs
	public ExprTree createOpOut(Location location, VarnodeTpl outvn, OpCode opc, ExprTree vn1,
			ExprTree vn2) {
		entry("createOpOut", location, outvn, opc, vn1, vn2);
		vn1.ops.appendAll(vn2.ops);
		vn2.ops.clear();
		OpTpl op = new OpTpl(location, opc);
		op.addInput(vn1.outvn);
		op.addInput(vn2.outvn);
		vn2.outvn = null;
		op.setOutput(outvn);
		vn1.ops.push_back(op);
		vn1.outvn = new VarnodeTpl(location, outvn);
		return vn1;
	}

	public ExprTree createOpOutUnary(Location location, VarnodeTpl outvn, OpCode opc, ExprTree vn) {
		entry("createOpOutUnary", location, outvn, opc, vn);
		OpTpl op = new OpTpl(location, opc);
		op.addInput(vn.outvn);
		op.setOutput(outvn);
		vn.ops.push_back(op);
		vn.outvn = new VarnodeTpl(location, outvn);
		return vn;
	}

	// Create new expression by creating op with given -opc-
	// and single input vn. Free the input expression
	public VectorSTL<OpTpl> createOpNoOut(Location location, OpCode opc, ExprTree vn) {
		entry("createOpNoOut", opc, vn);
		OpTpl op = new OpTpl(location, opc);
		op.addInput(vn.outvn);
		vn.outvn = null; // There is no longer an output to this expression
		VectorSTL<OpTpl> res = vn.ops;
		vn.ops = null;
		res.push_back(op);
		return res;
	}

	public VectorSTL<OpTpl> createOpNoOut(Location location, OpCode opc, ExprTree vn1, ExprTree vn2) {
		// Create new expression by creating op with given -opc-
		// and inputs vn1 and vn2. Free the input expressions
		entry("createOpNoOut", opc, vn1, vn2);
		VectorSTL<OpTpl> res = vn1.ops;
		vn1.ops = null;
		res.appendAll(vn2.ops);
		vn2.ops.clear();
		OpTpl op = new OpTpl(location, opc);
		op.addInput(vn1.outvn);
		vn1.outvn = null;
		op.addInput(vn2.outvn);
		vn2.outvn = null;
		res.push_back(op);
		return res;
	}

	public VectorSTL<OpTpl> createOpConst(Location location, OpCode opc, long val) {
		entry("createOpConst", location, opc, val);
		VarnodeTpl vn =
			new VarnodeTpl(location, new ConstTpl(getConstantSpace()), new ConstTpl(
				ConstTpl.const_type.real, val), new ConstTpl(ConstTpl.const_type.real, 4));
		VectorSTL<OpTpl> res = new VectorSTL<OpTpl>();
		OpTpl op = new OpTpl(location, opc);
		op.addInput(vn);
		res.push_back(op);
		return res;
	}

	// Create new load expression, free ptr expression
	public ExprTree createLoad(Location location, StarQuality qual, ExprTree ptr) {
		entry("createLoad", location, qual, ptr);
		VarnodeTpl outvn = buildTemporary(location);
		OpTpl op = new OpTpl(location, OpCode.CPUI_LOAD);
		VarnodeTpl spcvn =
			new VarnodeTpl(location, new ConstTpl(getConstantSpace()), qual.getId(), new ConstTpl(
				ConstTpl.const_type.real, 8));
		op.addInput(spcvn);
		op.addInput(ptr.outvn);
		op.setOutput(outvn);
		ptr.ops.push_back(op);
		if (qual.getSize() > 0) {
			force_size(outvn, new ConstTpl(ConstTpl.const_type.real, qual.getSize()), ptr.ops);
		}
		ptr.outvn = new VarnodeTpl(location, outvn);
		return ptr;
	}

	public VectorSTL<OpTpl> createStore(Location location, StarQuality qual, ExprTree ptr,
			ExprTree val) {
		entry("createStore", location, qual, ptr, val);
		VectorSTL<OpTpl> res = ptr.ops;
		ptr.ops = null;
		res.appendAll(val.ops);
		val.ops.clear();
		OpTpl op = new OpTpl(location, OpCode.CPUI_STORE);
		VarnodeTpl spcvn =
			new VarnodeTpl(location, new ConstTpl(getConstantSpace()), qual.getId(), new ConstTpl(
				ConstTpl.const_type.real, 8));
		op.addInput(spcvn);
		op.addInput(ptr.outvn);
		op.addInput(val.outvn);
		res.push_back(op);
		force_size(val.outvn, new ConstTpl(ConstTpl.const_type.real, qual.getSize()), res);
		ptr.outvn = null;
		val.outvn = null;
		return res;
	}

	// Create userdefined pcode op, given symbol and parameters
	public ExprTree createUserOp(UserOpSymbol sym, VectorSTL<ExprTree> param) {
		entry("createUserOp", sym, param);
		VarnodeTpl outvn = buildTemporary(sym.location);
		ExprTree res = new ExprTree(sym.getLocation());
		res.ops = createUserOpNoOut(sym.getLocation(), sym, param);
		res.ops.back().setOutput(outvn);
		res.outvn = new VarnodeTpl(sym.location, outvn);
		return res;
	}

	public VectorSTL<OpTpl> createUserOpNoOut(Location location, UserOpSymbol sym,
			VectorSTL<ExprTree> param) {
		entry("createUserOpNoOut", sym, param);
		OpTpl op = new OpTpl(location, OpCode.CPUI_CALLOTHER);
		VarnodeTpl vn =
			new VarnodeTpl(sym.location, new ConstTpl(getConstantSpace()), new ConstTpl(
				ConstTpl.const_type.real, sym.getIndex()),
				new ConstTpl(ConstTpl.const_type.real, 4));
		op.addInput(vn);
		return ExprTree.appendParams(op, param);
	}

	public ExprTree createVariadic(Location location,OpCode opc,VectorSTL<ExprTree> param) {
		entry("createVariadic", location, opc, param);
		VarnodeTpl outvn = buildTemporary(location);
		ExprTree res = new ExprTree(location);
		OpTpl op = new OpTpl(location, opc);
		res.ops = ExprTree.appendParams(op, param);
		res.ops.back().setOutput(outvn);
		res.outvn = new VarnodeTpl(location,outvn);
		return res;
	}

	// Build a truncated form basevn that matches the bitrange [ bitoffset, numbits ] if possible
	// using just ConstTpl (offset_plus) mechanics, otherwise return null
	public VarnodeTpl buildTruncatedVarnode(Location loc, VarnodeTpl basevn, int bitoffset,
			int numbits) {
		int byteoffset = bitoffset / 8;		// Convert to byte units
		int numbytes = numbits / 8;
		long fullsz = 0;
		if (basevn.getSize().getType() == const_type.real) {
			// If we know the size of base, make sure the bit range is in bounds
			fullsz = basevn.getSize().getReal();
			if (fullsz == 0) {
				return null;
			}
			if (byteoffset + numbytes > fullsz) {
				throw new SleighError(String.format("Requested bit range out of bounds -- %d > %d",
					(byteoffset + numbytes), fullsz), loc);
			}
		}

		if ((bitoffset % 8) != 0) {
			return null;
		}
		if ((numbits % 8) != 0) {
			return null;
		}

		if (basevn.getSpace().isUniqueSpace()) {
			return null;
		}

		const_type offset_type = basevn.getOffset().getType();
		if ((offset_type != const_type.real) && (offset_type != const_type.handle)) {
			return null;
		}

		ConstTpl specialoff;
		if (offset_type == const_type.handle) {
			// We put in the correct adjustment to offset assuming things are little endian
			// We defer the correct big endian calculation until after the consistency check
			// because we need to know the subtable export sizes
			specialoff =
				new ConstTpl(const_type.handle, basevn.getOffset().getHandleIndex(),
					v_field.v_offset_plus, byteoffset);
		}
		else {
			if (basevn.getSize().getType() != const_type.real) {
				throw new SleighError("Could not construct requested bit range", loc);
			}
			long plus;
			if (getDefaultSpace().isBigEndian()) {
				plus = fullsz - (byteoffset + numbytes);
			}
			else {
				plus = byteoffset;
			}
			specialoff = new ConstTpl(const_type.real, basevn.getOffset().getReal() + plus);
		}
		VarnodeTpl res =
			new VarnodeTpl(loc, basevn.getSpace(), specialoff, new ConstTpl(const_type.real,
				numbytes));
		return res;
	}

	// Take output of res expression, combine with constant,
	// using opc operation, return the resulting expression
	public void appendOp(Location location, OpCode opc, ExprTree res, long constval, int constsz) {
		entry("appendOp", location, opc, res, constval, constsz);
		OpTpl op = new OpTpl(location, opc);
		VarnodeTpl constvn =
			new VarnodeTpl(location, new ConstTpl(getConstantSpace()), new ConstTpl(
				ConstTpl.const_type.real, constval),
				new ConstTpl(ConstTpl.const_type.real, constsz));
		VarnodeTpl outvn = buildTemporary(location);
		op.addInput(res.outvn);
		op.addInput(constvn);
		op.setOutput(outvn);
		res.ops.push_back(op);
		res.outvn = new VarnodeTpl(location, outvn);
	}

	// Create an expression assigning the rhs to a bitrange within sym
	public VectorSTL<OpTpl> assignBitRange(Location location, VarnodeTpl vn, int bitoffset,
			int numbits, ExprTree rhs) {
		entry("assignBitRange", location, vn, bitoffset, numbits, rhs);
		String errmsg = "";
		if (numbits == 0) {
			errmsg = "Size of bitrange is zero";
		}
		int smallsize = (numbits + 7) / 8; // Size of input (output of rhs)
		boolean shiftneeded = (bitoffset != 0);
		boolean zextneeded = true;
		long mask = 2;
		mask = ~(((mask << (numbits - 1)) - 1) << bitoffset);

		if (vn.getSize().getType() == ConstTpl.const_type.real) {
			// If we know the size of the bitranged varnode, we can
			// do some immediate checks, and possibly simplify things
			int symsize = (int) vn.getSize().getReal();
			if (symsize > 0) {
				zextneeded = (symsize > smallsize);
			}
			symsize *= 8; // Convert to number of bits
			if ((bitoffset >= symsize) || (bitoffset + numbits > symsize)) {
				errmsg = "Assigned bitrange is bad";
			}
			else if ((bitoffset == 0) && (numbits == symsize)) {
				errmsg = "Assigning to bitrange is superfluous";
			}
		}

		if (errmsg.length() > 0) { // Was there an error condition
			reportError(location, errmsg); // Report the error
			VectorSTL<OpTpl> resops = rhs.ops; // Passthru old expression
			rhs.ops = null;
			return resops;
		}

		// We know what the size of the input has to be
		force_size(rhs.outvn, new ConstTpl(ConstTpl.const_type.real, smallsize), rhs.ops);

		ExprTree res;
		VarnodeTpl finalout = buildTruncatedVarnode(location, vn, bitoffset, numbits);
		if (finalout != null) {
			res = createOpOutUnary(location, finalout, OpCode.CPUI_COPY, rhs);
		}
		else {
			if (bitoffset + numbits > 64) {
				errmsg = "Assigned bitrange extends past first 64 bits";
			}
			res = new ExprTree(location, vn);
			appendOp(location, OpCode.CPUI_INT_AND, res, mask, 0);
			if (zextneeded) {
				createOp(location, OpCode.CPUI_INT_ZEXT, rhs);
			}
			if (shiftneeded) {
				appendOp(location, OpCode.CPUI_INT_LEFT, rhs, bitoffset, 4);
			}

			finalout = new VarnodeTpl(location, vn);
			res = createOpOut(location, finalout, OpCode.CPUI_INT_OR, res, rhs);
		}
		if (errmsg.length() > 0) {
			reportError(location, errmsg);
		}
		VectorSTL<OpTpl> resops = res.ops;
		res.ops = null;
		return resops;
	}

	// Create an expression computing the indicated bitrange of sym
	// The result is truncated to the smallest byte size that can
	// contain the indicated number of bits. The result has the
	// desired bits shifted all the way to the right
	public ExprTree createBitRange(Location location, SpecificSymbol sym, int bitoffset, int numbits) {
		entry("createBitRange", location, sym, bitoffset, numbits);
		String errmsg = "";
		if (numbits == 0) {
			errmsg = "Size of bitrange is zero";
		}
		VarnodeTpl vn = sym.getVarnode();
		int finalsize = (numbits + 7) / 8; // Round up to neareast byte size
		int truncshift = 0;
		boolean maskneeded = ((numbits % 8) != 0);
		boolean truncneeded = true;

		// Special case where we can set the size, without invoking
		// a truncation operator
		if ((errmsg.length() == 0) && (bitoffset == 0) && (!maskneeded)) {
			if ((vn.getSpace().getType() == ConstTpl.const_type.handle) && vn.isZeroSize()) {
				vn.setSize(new ConstTpl(ConstTpl.const_type.real, finalsize));
				ExprTree res = new ExprTree(sym.getLocation(), vn);
				// VarnodeTpl *cruft = buildTemporary();
				// delete cruft;
				return res;
			}
		}

		if (errmsg.length() == 0) {
			VarnodeTpl truncvn = buildTruncatedVarnode(location, vn, bitoffset, numbits);
			if (truncvn != null) {		// If we are able to construct a simple truncated varnode
				ExprTree res = new ExprTree(location, truncvn);		// Return just the varnode as an expression
				return res;
			}
		}

		if (vn.getSize().getType() == ConstTpl.const_type.real) {
			// If we know the size of the input varnode, we can
			// do some immediate checks, and possibly simplify things
			int insize = (int) vn.getSize().getReal();
			if (insize > 0) {
				truncneeded = (finalsize < insize);
				insize *= 8; // Convert to number of bits
				if ((bitoffset >= insize) || (bitoffset + numbits > insize)) {
					errmsg = "Bitrange is bad";
				}
				if (maskneeded && ((bitoffset + numbits) == insize)) {
					maskneeded = false;
				}
			}
		}

		long mask = 2;
		mask = ((mask << (numbits - 1)) - 1);

		if (truncneeded && ((bitoffset % 8) == 0)) {
			truncshift = bitoffset / 8;
			bitoffset = 0;
		}

		if ((bitoffset == 0) && (!truncneeded) && (!maskneeded)) {
			errmsg = "Superfluous bitrange";
		}

		if (maskneeded && finalsize > 8) {
			errmsg =
				"Illegal masked bitrange producing varnode larger than 64 bits: " + sym.getName();
		}

		ExprTree res = new ExprTree(sym.getLocation(), vn);

		if (errmsg.length() > 0) { // Check for error condition
			reportError(location, errmsg);
			return res;
		}

		if (bitoffset != 0) {
			appendOp(location, OpCode.CPUI_INT_RIGHT, res, bitoffset, 4);
		}
		if (truncneeded) {
			appendOp(location, OpCode.CPUI_SUBPIECE, res, truncshift, 4);
		}
		if (maskneeded) {
			appendOp(location, OpCode.CPUI_INT_AND, res, mask, finalsize);
		}
		force_size(res.outvn, new ConstTpl(ConstTpl.const_type.real, finalsize), res.ops);
		return res;
	}

	// Produce constant varnode that is the offset
	// portion of varnode -var-
	public VarnodeTpl addressOf(VarnodeTpl var, int size) {
		entry("addressOf", var, size);
		if (size == 0) { // If no size specified
			if (var.getSpace().getType() == ConstTpl.const_type.spaceid) {
				AddrSpace spc = var.getSpace().getSpace(); // Look to the
				// particular space
				size = spc.getAddrSize(); // to see if it has a standard
				// address size
			}
		}
		VarnodeTpl res;
		if ((var.getOffset().getType() == ConstTpl.const_type.real) &&
			(var.getSpace().getType() == ConstTpl.const_type.spaceid)) {
			AddrSpace spc = var.getSpace().getSpace();
			res =
				new VarnodeTpl(var.location, new ConstTpl(getConstantSpace()), new ConstTpl(
					ConstTpl.const_type.real, var.getOffset().getReal() >> spc.getScale()),
					new ConstTpl(ConstTpl.const_type.real, size));
		}
		else {
			res =
				new VarnodeTpl(var.location, new ConstTpl(getConstantSpace()), var.getOffset(),
					new ConstTpl(ConstTpl.const_type.real, size));
		}
		return res;
	}

	// Find something to fill in zero size varnode
	// j is the slot we are trying to fill (-1=output)
	// Don't check output for non-zero if inputonly is true
	public void matchSize(int j, OpTpl op, boolean inputonly, VectorSTL<OpTpl> ops) {
//        entry("matchSize", j, op, inputonly, ops);
		VarnodeTpl match = null;
		VarnodeTpl vt;
		int i, inputsize;

		vt = (j == -1) ? op.getOut() : op.getIn(j);
		if (!inputonly) {
			if (op.getOut() != null) {
				if (!op.getOut().isZeroSize()) {
					match = op.getOut();
				}
			}
		}
		inputsize = op.numInput();
		for (i = 0; i < inputsize; ++i) {
			if (match != null) {
				break;
			}
			if (op.getIn(i).isZeroSize()) {
				continue;
			}
			match = op.getIn(i);
		}
		if (match != null) {
			force_size(vt, match.getSize(), ops);
		}
	}

	public void fillinZero(OpTpl op, VectorSTL<OpTpl> ops) { // Try to get rid of
		// zero size varnodes in
		// op
		// Right now this is written assuming operands for the constructor are
		// are built before any other pcode in the constructor is generated

//        entry("fillinZero", op, ops);
		int inputsize, i;

		switch (op.getOpcode()) {
			case CPUI_COPY: // Instructions where all inputs and output are same
				// size
			case CPUI_INT_ADD:
			case CPUI_INT_SUB:
			case CPUI_INT_2COMP:
			case CPUI_INT_NEGATE:
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
			case CPUI_FLOAT_NEG:
			case CPUI_FLOAT_ABS:
			case CPUI_FLOAT_SQRT:
			case CPUI_FLOAT_CEIL:
			case CPUI_FLOAT_FLOOR:
			case CPUI_FLOAT_ROUND:
				if ((op.getOut() != null) && (op.getOut().isZeroSize())) {
					matchSize(-1, op, false, ops);
				}
				inputsize = op.numInput();
				for (i = 0; i < inputsize; ++i) {
					if (op.getIn(i).isZeroSize()) {
						matchSize(i, op, false, ops);
					}
				}
				break;
			case CPUI_INT_EQUAL: // Instructions with bool output
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
			case CPUI_FLOAT_NAN:
			case CPUI_BOOL_NEGATE:
			case CPUI_BOOL_XOR:
			case CPUI_BOOL_AND:
			case CPUI_BOOL_OR:
				if (op.getOut().isZeroSize()) {
					force_size(op.getOut(), new ConstTpl(ConstTpl.const_type.real, 1), ops);
				}
				inputsize = op.numInput();
				for (i = 0; i < inputsize; ++i) {
					if (op.getIn(i).isZeroSize()) {
						matchSize(i, op, true, ops);
					}
				}
				break;
			// The shift amount does not necessarily have to be the same size
			// But if no size is specified, assume it is the same size
			case CPUI_INT_LEFT:
			case CPUI_INT_RIGHT:
			case CPUI_INT_SRIGHT:
				if (op.getOut().isZeroSize()) {
					if (!op.getIn(0).isZeroSize()) {
						force_size(op.getOut(), op.getIn(0).getSize(), ops);
					}
				}
				else if (op.getIn(0).isZeroSize()) {
					force_size(op.getIn(0), op.getOut().getSize(), ops);
				}
				// fallthru to subpiece constant check
			case CPUI_SUBPIECE:
				if (op.getIn(1).isZeroSize()) {
					force_size(op.getIn(1), new ConstTpl(ConstTpl.const_type.real, 4), ops);
				}
				break;
			case CPUI_CPOOLREF:
				if (op.getOut().isZeroSize() && (!op.getIn(0).isZeroSize())) {
					force_size(op.getOut(),op.getIn(0).getSize(),ops);
				}
				if (op.getIn(0).isZeroSize() && (!op.getOut().isZeroSize())) {
					force_size(op.getIn(0),op.getOut().getSize(),ops);
				}
				for(i=1;i<op.numInput();++i) {
					force_size(op.getIn(i), new ConstTpl(ConstTpl.const_type.real, 8), ops);
				}
			default:
				break;
		}
	}

	public boolean propagateSize(ConstructTpl ct) {
		// Fill in size for varnodes
		// with size 0
		// Return first OpTpl with a size 0 varnode
		// that cannot be filled in or NULL otherwise
		entry("propagateSize", ct);
		VectorSTL<OpTpl> zerovec = new VectorSTL<OpTpl>(), zerovec2 = new VectorSTL<OpTpl>();
		IteratorSTL<OpTpl> iter;
		int lastsize;

		for (iter = ct.getOpvec().begin(); !iter.isEnd(); iter.increment()) {
			if (iter.get().isZeroSize()) {
				fillinZero(iter.get(), ct.getOpvec());
				if (iter.get().isZeroSize()) {
					zerovec.push_back(iter.get());
				}
			}
		}
		lastsize = zerovec.size() + 1;
		while (zerovec.size() < lastsize) {
			lastsize = zerovec.size();
			zerovec2 = new VectorSTL<OpTpl>();
			for (iter = zerovec.begin(); !iter.isEnd(); iter.increment()) {
				fillinZero(iter.get(), ct.getOpvec());
				if (iter.get().isZeroSize()) {
					zerovec2.push_back(iter.get());
				}
			}
			zerovec = zerovec2;
		}
		if (lastsize != 0) {
			return false;
		}
		return true;
	}

	public static void entry(String name, Object... args) {
		StringBuilder sb = new StringBuilder();
		sb.append(name).append("(");
		sb.append(Arrays.stream(args).map(Object::toString).collect(Collectors.joining(", ")));
		sb.append(")");

		log.trace(sb.toString());
	}

	static boolean isLocationIsh(Object o) {
		if (o instanceof Location) {
			return true;
		}
		if (o instanceof List) {
			List<?> l = (List<?>) o;
			for (Object t : l) {
				if (isLocationIsh(t)) {
					return true;
				}
			}
		}
		if (o instanceof VectorSTL) {
			VectorSTL<?> v = (VectorSTL<?>) o;
			for (Object t : v) {
				if (isLocationIsh(t)) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * EXTREMELY IMPORTANT: keep this up to date with isInternalFunction below!!!
	 * Lookup the given identifier as part of parsing p-code with functional syntax.
	 * Build the resulting p-code expression object from the parsed operand expressions.
	 * @param location identifies the file/line where the p-code is parsed from
	 * @param name is the given functional identifier
	 * @param operands is the ordered list of operand expressions
	 * @return the new expression (ExprTree) object
	 */
	public Object findInternalFunction(Location location, String name, VectorSTL<ExprTree> operands) {
		ExprTree r = null;
		ExprTree s = null;
		if (operands.size() > 0) {
			r = operands.get(0);
		}
		if (operands.size() > 1) {
			s = operands.get(1);
		}

		if ("zext".equals(name) && hasOperands(1, operands, location, name)) {
			return createOp(location, OpCode.CPUI_INT_ZEXT, r);
		}
		if ("carry".equals(name) && hasOperands(2, operands, location, name)) {
			return createOp(location, OpCode.CPUI_INT_CARRY, r, s);
		}
		if ("sext".equals(name) && hasOperands(1, operands, location, name)) {
			return createOp(location, OpCode.CPUI_INT_SEXT, r);
		}
		if ("scarry".equals(name) && hasOperands(2, operands, location, name)) {
			return createOp(location, OpCode.CPUI_INT_SCARRY, r, s);
		}
		if ("sborrow".equals(name) && hasOperands(2, operands, location, name)) {
			return createOp(location, OpCode.CPUI_INT_SBORROW, r, s);
		}
		if ("abs".equals(name) && hasOperands(1, operands, location, name)) {
			return createOp(location, OpCode.CPUI_FLOAT_ABS, r);
		}
		if ("nan".equals(name) && hasOperands(1, operands, location, name)) {
			return createOp(location, OpCode.CPUI_FLOAT_NAN, r);
		}
		if ("sqrt".equals(name) && hasOperands(1, operands, location, name)) {
			return createOp(location, OpCode.CPUI_FLOAT_SQRT, r);
		}
		if ("ceil".equals(name) && hasOperands(1, operands, location, name)) {
			return createOp(location, OpCode.CPUI_FLOAT_CEIL, r);
		}
		if ("floor".equals(name) && hasOperands(1, operands, location, name)) {
			return createOp(location, OpCode.CPUI_FLOAT_FLOOR, r);
		}
		if ("round".equals(name) && hasOperands(1, operands, location, name)) {
			return createOp(location, OpCode.CPUI_FLOAT_ROUND, r);
		}
		if ("int2float".equals(name) && hasOperands(1, operands, location, name)) {
			return createOp(location, OpCode.CPUI_FLOAT_INT2FLOAT, r);
		}
		if ("float2float".equals(name) && hasOperands(1, operands, location, name)) {
			return createOp(location, OpCode.CPUI_FLOAT_FLOAT2FLOAT, r);
		}
		if ("trunc".equals(name) && hasOperands(1, operands, location, name)) {
			return createOp(location, OpCode.CPUI_FLOAT_TRUNC, r);
		}
		if ("delayslot".equals(name) && hasOperands(1, operands, location, name)) {
			return createOpConst(location, OpCode.CPUI_INDIRECT, r.outvn.getOffset().getReal());
		}
		if ("cpool".equals(name)) {
			if (operands.size() >= 2) {
				return createVariadic(location, OpCode.CPUI_CPOOLREF, operands);
			}
			reportError(location,name+"() expects at least two arguments");
		}
		if ("newobject".equals(name)) {
			if (operands.size() >= 1) {
				return createVariadic(location, OpCode.CPUI_NEW, operands);
			}
			reportError(location,name+"() expects at least one argument");
		}
		if ("popcount".equals(name) && hasOperands(1, operands, location, name)) {
			return createOp(location, OpCode.CPUI_POPCOUNT, r);
		}

		return null;
	}

	private boolean hasOperands(int targetNumOperands, VectorSTL<ExprTree> operands,
			Location location, String name) {
		if (operands.size() == targetNumOperands) {
			return true;
		}
		reportError(location, name + "() expects " + targetNumOperands + " argument" +
			(targetNumOperands == 1 ? "" : "s") + "; found " + operands.size());
		return false;
	}

	/**
	 * EXTREMELY IMPORTANT: keep this up to date with findInternalFunction above!!!
	 * Determine if the given identifier is a sleigh internal function. Used to
	 * prevent user-defined p-code names from colliding with internal names
	 * @param name is the given identifier to check
	 * @return true if the identifier is a reserved internal function
	 */
	public boolean isInternalFunction(String name) {
		if ("zext".equals(name)) {
			return true;
		}
		if ("carry".equals(name)) {
			return true;
		}
		if ("sext".equals(name)) {
			return true;
		}
		if ("scarry".equals(name)) {
			return true;
		}
		if ("sborrow".equals(name)) {
			return true;
		}
		if ("abs".equals(name)) {
			return true;
		}
		if ("nan".equals(name)) {
			return true;
		}
		if ("sqrt".equals(name)) {
			return true;
		}
		if ("ceil".equals(name)) {
			return true;
		}
		if ("floor".equals(name)) {
			return true;
		}
		if ("round".equals(name)) {
			return true;
		}
		if ("int2float".equals(name)) {
			return true;
		}
		if ("float2float".equals(name)) {
			return true;
		}
		if ("trunc".equals(name)) {
			return true;
		}
		if ("delayslot".equals(name)) {
			return true;
		}
		if ("cpool".equals(name)) {
			return true;
		}
		if ("newobject".equals(name)) {
			return true;
		}
		if ("popcount".equals(name)) {
			return true;
		}

		return false;
	}
}
