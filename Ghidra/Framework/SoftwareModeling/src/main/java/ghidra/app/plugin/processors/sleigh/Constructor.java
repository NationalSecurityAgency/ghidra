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
/*
 * Created on Feb 8, 2005
 *
 */
package ghidra.app.plugin.processors.sleigh;

import java.util.*;

import ghidra.app.plugin.processors.sleigh.symbol.*;
import ghidra.app.plugin.processors.sleigh.template.ConstructTpl;
import ghidra.app.plugin.processors.sleigh.template.HandleTpl;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * 
 *
 * The primary sleigh concept representing a semantic action
 * taking operands (semantic values) as input
 * producing a semantic value as output
 * matching a particular pattern
 * printing in a certain way
*/
public class Constructor implements Comparable<Constructor> {

	private SubtableSymbol parent;
	private OperandSymbol[] operands;
	private String[] separators;
	private String[] printpiece;
	private ContextChange[] context;
	private ConstructTpl templ;		// The main p-code template section
	private ArrayList<ConstructTpl> namedtempl;	// Other named p-code template sections
	private int minimumlength;		// Minimum length taken up by Constructor
	private int id;					// Unique id of constructor within subtable
	private int firstwhitespace;	// Index of first whitespace piece in -printpiece-
	private int lineno; /* Line number of constructor definition
						in original (uncompiled) specfile */

	private int flowthruindex;
	private String sourceFile;

	public Constructor() {
		parent = null;
		templ = null;
		namedtempl = null;
		firstwhitespace = -1;
		flowthruindex = -1;
	}

	@Override
	public String toString() {
		return "line" + lineno + "(id" + parent.getId() + "." + id + ")";
	}

	public List<String> getPrintPieces() {
		return Arrays.asList(printpiece);
	}

	public int getFlowthruIndex() {
		return flowthruindex;
	}

	public int getMinimumLength() {
		return minimumlength;
	}

	public void setId(int val) {
		id = val;
	}

	public int getId() {
		return id;
	}

	public int getLineno() {
		return lineno;
	}

	public SubtableSymbol getParent() {
		return parent;
	}

	public int getNumOperands() {
		return operands.length;
	}

	public OperandSymbol getOperand(int i) {
		return operands[i];
	}

	public ConstructTpl getTempl() {
		return templ;
	}

	public List<ContextChange> getContextChanges() {
		return Collections.unmodifiableList(Arrays.asList(context));
	}

	public String print(ParserWalker walker) throws MemoryAccessException {
		String res = "";
		for (String element : printpiece) {
			if (element.length() != 0) {
				if (element.charAt(0) == '\n') {
					int index = element.charAt(1) - 'A';
					res += operands[index].print(walker);
				}
				else {
					res += element;
				}
			}
		}
		return res;
	}

	public String printSeparator(int separatorIndex) {

		// Separator is all chars to the left of the corresponding operand
		// The mnemonic (first sequence of contiguous non-space print-pieces)
		// is ignored when identifying the first separator (index 0) and the 
		// operand which immediately follows.
		// NOTE: sleigh "operands" may appear as part of mnemonic so the 
		// separator cache may be slightly over-allocated.  
		if (separatorIndex < 0 || separatorIndex > operands.length) {
			return null;
		}

		String cachedSeparator = separators[separatorIndex];
		if (cachedSeparator != null) {
			if (cachedSeparator.length() == 0) {
				return null;
			}
			return cachedSeparator;
		}

		// skip mnemonic and set curPos to first print-piece associated with operand 0
		int curPos = 0;
		while (curPos < printpiece.length &&
			(printpiece[curPos].length() == 0 || printpiece[curPos].charAt(0) != ' ')) {
			curPos++;
		}
		curPos++;

		int opIndex = 0;
		StringBuilder buf = new StringBuilder();
		for (int i = curPos; i < printpiece.length && opIndex <= separatorIndex; i++) {
			if (printpiece[i].length() != 0) {
				if (printpiece[i].charAt(0) == '\n') {
					if (opIndex == separatorIndex) {
						break;
					}
					opIndex++;
				}
				else if (opIndex == separatorIndex) {
					buf.append(printpiece[i]);
				}
			}
		}
		String separator = buf.toString();
		separator = separator.replaceAll(",\\s+", ",");
		separators[separatorIndex] = separator;
		if (separator.length() == 0) {
			return null;
		}
		return separator;
	}

	public void printList(ParserWalker walker, ArrayList<Object> list)
			throws MemoryAccessException {

		int opSymbolCnt = 0;
		FixedHandle lastHandle = null;
		int lastHandleIndex = -1;

		for (String element : printpiece) {
			int prevSize = list.size();
			if (element.length() != 0) {
				if (element.charAt(0) == '\n') {
					int index = element.charAt(1) - 'A';
					operands[index].printList(walker, list);
					if (prevSize != list.size() && ++opSymbolCnt == 1) {
						// Identify sole handle which can be fixed
						for (int n = prevSize; n < list.size(); n++) {
							Object obj = list.get(n);
							if (!(obj instanceof FixedHandle)) {
								continue;
							}
							if (lastHandle != null) {
								// can't fix multiple handles
								lastHandle = null;
								break;
							}
							lastHandle = (FixedHandle) obj;
							lastHandleIndex = index;
						}
					}
				}
				else {
					for (int j = 0; j < element.length(); ++j) {
						list.add(new Character(element.charAt(j)));
					}
				}
			}
		}

		// Fix constant operand exported as address
		if (opSymbolCnt == 1 && lastHandle != null && lastHandle.fixable && templ != null) {
			HandleTpl res = templ.getResult();
			if (res != null) {	// Pop up handle to containing operand
				res.fixPrintPiece(lastHandle, walker, lastHandleIndex);
			}
		}
	}

	public String printMnemonic(ParserWalker walker) throws MemoryAccessException {
		String res = "";
		if (flowthruindex != -1) {
			Symbol sym = operands[flowthruindex].getDefiningSymbol();
			if (sym instanceof SubtableSymbol) {
				walker.pushOperand(flowthruindex);
				res = walker.getConstructor().printMnemonic(walker);
				walker.popOperand();
				return res;
			}
		}
		int endind = (firstwhitespace == -1) ? printpiece.length : firstwhitespace;
		for (int i = 0; i < endind; ++i) {
			if (printpiece[i].length() != 0) {
				if (printpiece[i].charAt(0) == '\n') {
					int index = printpiece[i].charAt(1) - 'A';
					res += operands[index].print(walker);
				}
				else {
					res += printpiece[i];
				}
			}
		}
		return res;
	}

	public String printBody(ParserWalker walker) throws MemoryAccessException {
		String res = "";
		if (flowthruindex != -1) {
			Symbol sym = operands[flowthruindex].getDefiningSymbol();
			if (sym instanceof SubtableSymbol) {
				walker.pushOperand(flowthruindex);
				res = walker.getConstructor().printBody(walker);
				walker.popOperand();
				return res;
			}
		}
		if (firstwhitespace == -1) {
			return res;	// Nothing to print
		}
		for (int i = firstwhitespace + 1; i < printpiece.length; ++i) {
			if (printpiece[i].length() != 0) {
				if (printpiece[i].charAt(0) == '\n') {
					int index = printpiece[i].charAt(1) - 'A';
					res += operands[index].print(walker);
				}
				else {
					res += printpiece[i];
				}
			}
		}
		return res;
	}

	/**
	 * Apply any operations on context for this Constructor to a
	 * particular InstructionContext
	 * @param walker the parser walker
	 * @param debug the debug logger
	 * @throws MemoryAccessException if the context failed to be applied.
	 */
	public void applyContext(ParserWalker walker, SleighDebugLogger debug)
			throws MemoryAccessException {
		for (ContextChange element : context) {
			element.apply(walker, debug);
		}
	}

	/**
	 * Retrieve a named p-code template section
	 * @param secnum is the id of the section to return
	 * @return the named section (or null)
	 */
	public ConstructTpl getNamedTempl(int secnum) {
		if (namedtempl == null) {
			return null;
		}
		if (secnum < namedtempl.size()) {
			return namedtempl.get(secnum);
		}
		return null;
	}

	public void restoreXml(XmlPullParser parser, SleighLanguage sleigh)
			throws UnknownInstructionException {
		XmlElement el = parser.start("constructor");
		SymbolTable symtab = sleigh.getSymbolTable();

		int myId = SpecXmlUtils.decodeInt(el.getAttribute("parent"));
		parent = (SubtableSymbol) symtab.findSymbol(myId);
		firstwhitespace = SpecXmlUtils.decodeInt(el.getAttribute("first"));
		minimumlength = SpecXmlUtils.decodeInt(el.getAttribute("length"));
		String sourceAndLine = el.getAttribute("line");
		String[] parts = sourceAndLine.split(":");
		if (parts.length != 2) {
			Msg.error(this, "Bad line attribute in .sla file");
			lineno = -1;
			sourceFile = "UNKNOWN";
		}
		else {
			lineno = Integer.parseInt(parts[1].trim());
			sourceFile = sleigh.getSourceFileIndexer().getFileName(Integer.parseInt(parts[0].trim()));
		}

		ArrayList<Object> oplist = new ArrayList<>();
		ArrayList<Object> piecelist = new ArrayList<>();
		ArrayList<Object> coplist = new ArrayList<>();
		XmlElement subel = parser.peek();
		while (!subel.getName().equals("constructor")) {
			if (subel.getName().equals("oper")) {
				myId = SpecXmlUtils.decodeInt(subel.getAttribute("id"));
				oplist.add(symtab.findSymbol(myId));
				parser.discardSubTree();
			}
			else if (subel.getName().equals("print")) {
				piecelist.add(subel.getAttribute("piece"));
				parser.discardSubTree();
			}
			else if (subel.getName().equals("opprint")) {
				myId = SpecXmlUtils.decodeInt(subel.getAttribute("id"));
				String operstring = "\n";
				char ind = (char) ('A' + myId);
				operstring += ind;
				piecelist.add(operstring);
				parser.discardSubTree();
			}
			else if (subel.getName().equals("context_op")) {
				ContextOp c_op = new ContextOp();
				c_op.restoreXml(parser, sleigh);
				coplist.add(c_op);
			}
			else if (subel.getName().equals("commit")) {
				ContextCommit c_op = new ContextCommit();
				c_op.restoreXml(parser, sleigh);
				coplist.add(c_op);
			}
			else {
				ConstructTpl curtempl = new ConstructTpl();
				int sectionid = curtempl.restoreXml(parser, sleigh.getAddressFactory());
				if (sectionid < 0) {
					if (templ != null) {
						throw new UnknownInstructionException("Duplicate main template section");
					}
					templ = curtempl;
				}
				else {
					if (namedtempl == null) {
						namedtempl = new ArrayList<>();
					}
					while (namedtempl.size() <= sectionid) {
						namedtempl.add(null);
					}
					if (namedtempl.get(sectionid) != null) {
						throw new UnknownInstructionException("Duplicate named template section");
					}
					namedtempl.set(sectionid, curtempl);
				}
			}
			subel = parser.peek();
		}
		operands = new OperandSymbol[oplist.size()];
		separators = new String[operands.length + 1];
		oplist.toArray(operands);
		printpiece = new String[piecelist.size()];
		piecelist.toArray(printpiece);
		context = new ContextChange[coplist.size()];
		coplist.toArray(context);
		if ((printpiece.length == 1) && (printpiece[0].length() >= 2) &&
			(printpiece[0].charAt(0) == '\n')) {
			flowthruindex = printpiece[0].charAt(1) - 'A';
		}
		else {
			flowthruindex = -1;
		}
		parser.end(el);
	}

	/**
	 * Return the indices of the operands in an array
	 * in the order they are printed (after the first white space)
	 * @return array of operand indices
	 */
	public int[] getOpsPrintOrder() {
		if (firstwhitespace == -1) {
			return new int[0];
		}
		int count = 0;
		for (int i = firstwhitespace + 1; i < printpiece.length; ++i) {
			if (printpiece[i].length() != 0 && printpiece[i].charAt(0) == '\n') {
				count += 1;
			}
		}
		int[] res = new int[count];
		count = 0;
		for (int i = firstwhitespace + 1; i < printpiece.length; ++i) {
			if (printpiece[i].length() != 0 && printpiece[i].charAt(0) == '\n') {
				res[count++] = printpiece[i].charAt(1) - 'A';
			}
		}
		return res;
	}

	/* ***************************** *
	 * Get these working as map keys *
	 * ***************************** */

	@Override
	public int compareTo(Constructor that) {
		int result;
		result = this.id - that.id;
		if (result != 0) {
			return result;
		}
		result = this.parent.getId() - that.parent.getId();
		if (result != 0) {
			return result;
		}
		return 0;
	}

	@Override
	public int hashCode() {
		return this.parent.getId() * 31 + id;
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof Constructor)) {
			return false;
		}
		Constructor that = (Constructor) obj;
		if (this.id != that.id) {
			return false;
		}
		if (this.parent.getId() != that.parent.getId()) {
			return false;
		}
		return true;
	}

	/**
	 * Returns the source file
	 * @return source file
	 */
	public String getSourceFile() {
		return sourceFile;
	}
}
