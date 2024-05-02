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
package ghidra.pcodeCPort.sleighbase;

import static ghidra.pcode.utils.SlaFormat.*;

import java.io.IOException;
import java.util.ArrayList;

import generic.stl.*;
import ghidra.pcodeCPort.context.SleighError;
import ghidra.pcodeCPort.pcoderaw.VarnodeData;
import ghidra.pcodeCPort.slghpatexpress.ContextField;
import ghidra.pcodeCPort.slghsymbol.*;
import ghidra.pcodeCPort.space.AddrSpace;
import ghidra.pcodeCPort.space.spacetype;
import ghidra.pcodeCPort.translate.Translate;
import ghidra.program.model.pcode.Encoder;
import ghidra.sleigh.grammar.SourceFileIndexer;

public abstract class SleighBase extends Translate implements NamedSymbolProvider {

	/**
	 * Note: The value of {@link #MAX_UNIQUE_SIZE}  must match the corresponding value
	 * defined by sleighbase.cc
	 */
	public static final long MAX_UNIQUE_SIZE = 128;  //Maximum size of a varnode in the unique space.  
													//Should match value in sleighbase.cc

	private VectorSTL<String> userop = new VectorSTL<>();
	private address_set varnode_xref = new address_set(); // Cross-reference registers by address
	protected SubtableSymbol root;
	protected SymbolTable symtab = new SymbolTable();
	protected int maxdelayslotbytes;	// Maximum number of bytes in a delayslot directive
	protected int unique_allocatemask;	// Bits that are guaranteed to be zero in the unique allocation scheme
	protected int numSections;		// Number of named sections
	protected SourceFileIndexer indexer;  //indexer for source files
										//used to provide source file info for constructors

	@Override
	public SleighSymbol findSymbol(String nm) {
		return symtab.findSymbol(nm);
	}

	public SleighSymbol findSymbol(int id) {
		return symtab.findSymbol(id);
	}

	SleighSymbol findGlobalSymbol(String nm) {
		return symtab.findGlobalSymbol(nm);
	}

	public SleighBase() {
		root = null;
		maxdelayslotbytes = 0;
		unique_allocatemask = 0;
		numSections = 0;
		indexer = new SourceFileIndexer();
	}

	public boolean isInitialized() {
		return (root != null);
	}

	protected void buildXrefs(ArrayList<SleighSymbol> errorPairs) {
		SymbolScope glb = symtab.getGlobalScope();
		glb.begin();
		IteratorSTL<SleighSymbol> iter;
		for (iter = glb.begin(); !iter.isEnd(); iter.increment()) {
			SleighSymbol sym = iter.get();
			if (sym.getType() == symbol_type.varnode_symbol) {
				Pair<IteratorSTL<VarnodeSymbol>, Boolean> res =
					varnode_xref.insert((VarnodeSymbol) sym);
				if (!res.second) {
					errorPairs.add(sym);
					errorPairs.add(res.first.get());
				}
			}
			else if (sym.getType() == symbol_type.userop_symbol) {
				int index = ((UserOpSymbol) sym).getIndex();
				while (userop.size() <= index) {
					userop.push_back("");
				}
				userop.set(index, sym.getName());
			}
			else if (sym.getType() == symbol_type.context_symbol) {
				ContextSymbol csym = (ContextSymbol) sym;
				ContextField field = (ContextField) csym.getPatternValue();
				int startbit = field.getStartBit();
				int endbit = field.getEndBit();
				registerContext(csym.getName(), startbit, endbit);
			}
		}
	}

	protected void reregisterContext() {
		// If the base is being reused with a new program, the context
		// variables need to be registered with the new program's database
		SymbolScope glb = symtab.getGlobalScope();
		IteratorSTL<SleighSymbol> iter;
		SleighSymbol sym;
		for (iter = glb.begin(); !iter.isEnd(); iter.increment()) {
			sym = iter.get();
			if (sym.getType() == symbol_type.context_symbol) {
				ContextSymbol csym = (ContextSymbol) sym;
				ContextField field = (ContextField) csym.getPatternValue();
				int startbit = field.getStartBit();
				int endbit = field.getEndBit();
				registerContext(csym.getName(), startbit, endbit);
			}
		}
	}

	@Override
	public VarnodeData getRegister(String nm) {
		VarnodeSymbol sym = (VarnodeSymbol) findSymbol(nm);
		if (sym == null) {
			throw new SleighError("Unknown register name '" + nm + "'", null);
		}
		if (sym.getType() != symbol_type.varnode_symbol) {
			throw new SleighError("Symbol is not a register '" + nm + "'", sym.location);
		}
		return sym.getFixedVarnode();
	}

	@Override
	public String getRegisterName(AddrSpace base, long off, int size) {
		VarnodeSymbol sym = new VarnodeSymbol(null, "", base, off, size);
		IteratorSTL<VarnodeSymbol> iter = varnode_xref.upper_bound(sym); // First point greater
																		// than offset
		if (iter.isBegin()) {
			return "";
		}
		iter.decrement();
		VarnodeData point = iter.get().getFixedVarnode();
		if (!point.space.equals(base)) {
			return "";
		}
		long offbase = point.offset;
		if (point.offset + point.size >= off + size) {
			return iter.get().getName();
		}

		while (!iter.isBegin()) {
			iter.decrement();
			VarnodeData point2 = iter.get().getFixedVarnode();
			if ((point2.space != base) || (point2.offset != offbase)) {
				return "";
			}
			if (point.offset + point2.size >= off + size) {
				return iter.get().getName();
			}
		}
		return "";
	}

	// Return list of all language defined user ops (with index)
	@Override
	public void getUserOpNames(VectorSTL<String> res) {
		res.clear();
		IteratorSTL<String> iter = userop.begin();
		while (!iter.isEnd()) {
			res.push_back(iter.get());
			iter.increment();
		}
	}

	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_SLEIGH);
		encoder.writeSignedInteger(ATTRIB_VERSION, FORMAT_VERSION);
		encoder.writeBool(ATTRIB_BIGENDIAN, isBigEndian());
		encoder.writeSignedInteger(ATTRIB_ALIGN, alignment);
		encoder.writeUnsignedInteger(ATTRIB_UNIQBASE, getUniqueBase());
		if (maxdelayslotbytes > 0) {
			encoder.writeUnsignedInteger(ATTRIB_MAXDELAY, maxdelayslotbytes);
		}
		if (unique_allocatemask != 0) {
			encoder.writeUnsignedInteger(ATTRIB_UNIQMASK, unique_allocatemask);
		}
		if (numSections != 0) {
			encoder.writeUnsignedInteger(ATTRIB_NUMSECTIONS, numSections);
		}
		indexer.encode(encoder);
		encoder.openElement(ELEM_SPACES);
		encoder.writeString(ATTRIB_DEFAULTSPACE, getDefaultSpace().getName());
		for (int i = 0; i < numSpaces(); ++i) {
			AddrSpace spc = getSpace(i);
			if ((spc.getType() == spacetype.IPTR_CONSTANT) ||
				(spc.getType() == spacetype.IPTR_FSPEC) || (spc.getType() == spacetype.IPTR_IOP)) {
				continue;
			}
			spc.encode(encoder);
		}
		encoder.closeElement(ELEM_SPACES);
		symtab.encode(encoder);
		encoder.closeElement(ELEM_SLEIGH);
	}

}
