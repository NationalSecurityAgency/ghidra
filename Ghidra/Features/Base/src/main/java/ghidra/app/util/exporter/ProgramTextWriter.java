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
package ghidra.app.util.exporter;

import java.io.*;
import java.util.ArrayList;

import ghidra.app.util.DisplayableEol;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.NoValueException;
import ghidra.util.task.TaskMonitor;

class ProgramTextWriter {

	// HTML tags
	private final static String BEGIN_ANCHOR = "<A NAME=\"";
	private final static String END_ANCHOR = "\"></A>";

	private final static String BYTES_DELIM = "";
	private final static String STRUCT_PREFIX = "|_";
	private final static int INDENT_SPACES = 3;

	private ProgramTextOptions options;
	private StringBuilder buffy = new StringBuilder();
	private PrintWriter writer;

	private Program program;
	private Listing listing;
	private Memory memory;
	private AddressSetView addressSet;
	private ReferenceManager referenceManager;
	private SymbolTable symbolTable;
	private Function currentFunction;

	ProgramTextWriter(File file, Program program, AddressSetView addrSet, TaskMonitor monitor,
			ProgramTextOptions options, ServiceProvider provider) throws FileNotFoundException {

		this.options = options;
		// Exit if options are INVALID
		int len = options.getAddrWidth() + options.getBytesWidth() + options.getPreMnemonicWidth() +
			options.getMnemonicWidth() + options.getOperandWidth() + options.getEolWidth();

		this.program = program;
		this.listing = program.getListing();
		this.memory = program.getMemory();
		this.referenceManager = program.getReferenceManager();
		this.symbolTable = program.getSymbolTable();

		// Record Starting Time
		long startTime = System.currentTimeMillis();
		long time = startTime;

		writer = new PrintWriter(new FileOutputStream(file));

		if (addrSet == null) {
			addressSet = program.getMemory();
		}
		else {
			addressSet = addrSet.intersect(memory);
		}

		CodeUnitIterator cuIterator = listing.getCodeUnits(addressSet, true);

		//boolean sk = false;
		if (options.isHTML()) {
			writer.print("<HTML><BODY BGCOLOR=#ffffe0>");
			writer.println("<FONT FACE=COURIER SIZE=3><STRONG><PRE>");
		}

		CodeUnitFormatOptions formatOptions = new CodeUnitFormatOptions(
			options.isShowBlockNameInOperands() ? CodeUnitFormatOptions.ShowBlockName.NON_LOCAL
					: CodeUnitFormatOptions.ShowBlockName.NEVER,
			CodeUnitFormatOptions.ShowNamespace.NON_LOCAL, null, true, // include register variable markup
			true, // include stack register variable markup
			true, // include inferred register variable markup
			true, // include extended reference markup
			true, // include scalar adjustment
			true, // include library names in namespace
			true // follow referenced pointers
		);

		CodeUnitFormat cuFormat = new CodeUnitFormat(formatOptions);

		////  M A I N   L O O P  //////////////////////////////////////////

		Address bytesRemovedRangeStart = null;
		Address bytesRemovedRangeEnd = null;
		Address nextAddressExpected = null;

		while (cuIterator.hasNext() && !monitor.isCancelled()) {
			CodeUnit currentCodeUnit = cuIterator.next();

			Address currentAddress = currentCodeUnit.getMinAddress();

			if (!addressSet.contains(currentAddress)) {
				continue;
			}

			long currTime = System.currentTimeMillis();
			if (currTime > (time + 1000)) {
				monitor.setMessage("Processing ... " + currentAddress);
				time = currTime;
			}

			//// Undefined Data Area ///////////////////////////////////////

			if ((!options.isShowUndefinedData()) && (currentCodeUnit instanceof Data) &&
				!((Data) currentCodeUnit).isDefined()) {
				if (bytesRemovedRangeStart == null) {
					bytesRemovedRangeStart = currentAddress;
				}
				else if (!nextAddressExpected.equals(currentAddress)) {
					insertUndefinedBytesRemovedMarker(bytesRemovedRangeStart, bytesRemovedRangeEnd);
					bytesRemovedRangeStart = currentAddress;
				}
				bytesRemovedRangeEnd = currentCodeUnit.getMaxAddress();
				nextAddressExpected = bytesRemovedRangeEnd.addWrap(1);
				if (options.isHTML() && currentCodeUnit.getReferenceIteratorTo().hasNext()) {
					writer.print(BEGIN_ANCHOR + toHREF(currentAddress) + END_ANCHOR);
				}
				continue;
			}
			if (bytesRemovedRangeStart != null) {
				insertUndefinedBytesRemovedMarker(bytesRemovedRangeStart, bytesRemovedRangeEnd);
				bytesRemovedRangeStart = null;
			}

			if (options.isHTML()) {
				writer.print(BEGIN_ANCHOR + toHREF(currentAddress) + END_ANCHOR);
			}

			currentFunction = listing.getFunctionContaining(currentAddress);
			boolean isFunctionEntryPoint =
				currentFunction != null && currentFunction.getEntryPoint().equals(currentAddress);

			//// Plate Property ////////////////////////////////////////////
			boolean cuHasPlate = false;
			if (options.isShowProperties()) {
				String[] plate = currentCodeUnit.getCommentAsArray(CodeUnit.PLATE_COMMENT);
				cuHasPlate = plate != null && plate.length > 0;
				if (cuHasPlate) {
					processPlate(currentCodeUnit, plate);
				}
				else if (isFunctionEntryPoint) {
					processPlate(currentCodeUnit, new String[] { "FUNCTION" });
				}
			}

			//// Function Signature and Header /////////////////////////////
			if (isFunctionEntryPoint) {
				String fill = genFill(options.getAddrWidth() + options.getBytesWidth());

				String repeatableComment = currentFunction.getRepeatableComment();
				if (repeatableComment != null) {
					writer.println(fill + options.getCommentPrefix() + repeatableComment);
				}
				writer.println(fill + options.getCommentPrefix() +
					currentFunction.getPrototypeString(false, false));

				Parameter[] params = currentFunction.getParameters();
				for (Parameter param : params) {
					processVariable(param);
				}

				Variable[] locals = currentFunction.getLocalVariables();
				for (Variable local : locals) {
					processVariable(local);
				}

				//StackVariable [] params = frame.getParameters();
				//for (int i = 0; i < params.length; ++i) {
				//    processStackVariable(params[i]);
				//}
				//StackVariable [] locals = frame.getLocals();
				//for (int i = 0; i < locals.length; ++i) {
				//    processStackVariable(locals[i]);
				//}
			}

			//// Pre-Comment ///////////////////////////////////////////////

			if (options.isShowComments()) {
				String[] pre = currentCodeUnit.getCommentAsArray(CodeUnit.PRE_COMMENT);
				if (pre != null && pre.length > 0) {
					String fill = genFill(options.getAddrWidth() + options.getBytesWidth());
					for (String element : pre) {
						writeComments(element, fill);
					}
				}
			}

			//// Labels ////////////////////////////////////////////////////

			ArrayList<String> symbolLines = new ArrayList<>();

			if (options.getLabelWidth() > 0 && (!isFunctionEntryPoint ||
				(isFunctionEntryPoint && options.isShowFunctionLabel()))) {
				Symbol[] symbols = currentCodeUnit.getSymbols();
				if (symbols.length > 0) {
					makePrimaryLastItem(symbols);
					for (Symbol symbol2 : symbols) {
						String symbol = symbol2.getName() + options.getLabelSuffix();
						symbolLines.add(clip(symbol, options.getLabelWidth(), true, true));
					}
				}
				else {
					Address nextAddr = currentAddress.next();
					if (nextAddr != null) {
						SymbolIterator it = symbolTable.getSymbolIterator(nextAddr, true);
						Symbol s = it.next();
						if (s != null &&
							s.getAddress().compareTo(currentCodeUnit.getMaxAddress()) <= 0) {
							// TODO: This does not appear to be consistent with code browser listing
							String symbol = SymbolUtilities.getDynamicOffcutName(currentAddress) +
								options.getLabelSuffix();
							symbolLines.add(clip(symbol, options.getLabelWidth(), true, true));
						}
					}
				}
			}

			//// Cross-references //////////////////////////////////////////

			ReferenceLineDispenser backRLD = (options.isShowBackReferences()
					? new ReferenceLineDispenser(false, currentCodeUnit, program, options)
					: new ReferenceLineDispenser());
			ReferenceLineDispenser fwdRLD = (options.isShowForwardReferences()
					? new ReferenceLineDispenser(true, currentCodeUnit, program, options)
					: new ReferenceLineDispenser());

			//// Process the labels and refs... ///////////////////

			String emptySymbolLine = genFill(options.getLabelWidth());

			int preSymbolWidth = options.getAddrWidth() + options.getBytesWidth();

			int backRefEmptyFlag = 0;
			while (!symbolLines.isEmpty() || backRLD.hasMoreLines() || fwdRLD.hasMoreLines()) {
				buffy = new StringBuilder();
				buffy.append(genFill(preSymbolWidth));
				if (symbolLines.isEmpty()) {
					buffy.append(emptySymbolLine);
				}
				else {
					buffy.append(symbolLines.remove(0));
				}
				if (backRLD.hasMoreLines()) {
					buffy.append(backRLD.getNextLine());
				}
				else {
					backRefEmptyFlag++;
				}
				if (backRefEmptyFlag > 0 && fwdRLD.hasMoreLines()) {
					buffy.append(fwdRLD.getNextLine());
				}
				writer.println(buffy.toString());
			}

			backRLD.dispose();
			fwdRLD.dispose();

			//// Line of Disassembled Code /////////////////////////////////

			buffy = new StringBuilder();

			processAddress(currentCodeUnit.getMinAddress(), null);
			processBytes(currentCodeUnit);
			processMnemonic(currentCodeUnit);
			processOperand(currentCodeUnit, cuFormat);

			//// End of Line Area //////////////////////////////////////////

			if (options.isShowComments()) {
				DisplayableEol displayableEol = new DisplayableEol(currentCodeUnit, false, false,
					false, true, 6 /* arbitrary! */, true, true);
				String[] eol = displayableEol.getComments();
				if (eol != null && eol.length > 0) {
					len = options.getAddrWidth() + options.getBytesWidth() +
						options.getPreMnemonicWidth() + options.getMnemonicWidth() +
						options.getOperandWidth();

					String fill = genFill(len);

					for (int i = 0; i < eol.length; ++i) {
						if (i > 0) {
							buffy.append(fill);
						}
						String eolcmt = options.getCommentPrefix() + eol[i];
						if (eolcmt.length() > options.getEolWidth()) {
							eolcmt = clip(eolcmt, options.getEolWidth(), true, true);
						}
						buffy.append(eolcmt);
						writer.println(buffy.toString());
						buffy = new StringBuilder();
					}
				}
			}

			if (buffy.length() > 0) {
				writer.println(buffy.toString());
			}
			buffy = new StringBuilder();

			//// Post Comment //////////////////////////////////////////////
			if (options.isShowComments()) {
				String[] post = currentCodeUnit.getCommentAsArray(CodeUnit.POST_COMMENT);
				if (post != null) {
					String fill = genFill(options.getAddrWidth() + options.getBytesWidth());
					for (String element : post) {
						writeComments(element, fill);
					}
				}
			}

			//// Structures ////////////////////////////////////////////////

			// now process any subdata; ie, arrays or structs

			if (currentCodeUnit instanceof Data) {
				if (options.isShowStructures()) {
					Data data = (Data) currentCodeUnit;
					processSubData(data, 1, cuFormat);
				}
			}

			//// Space Property ////////////////////////////////////////////

			if (options.isShowProperties() && currentCodeUnit.hasProperty("Space")) {
				try {
					processSpace(currentCodeUnit.getIntProperty("Space"));
				}
				catch (NoValueException e) {
					//no space property...ignore...
				}
			}

		} // End main loop

		if (bytesRemovedRangeStart != null) {
			insertUndefinedBytesRemovedMarker(bytesRemovedRangeStart, bytesRemovedRangeEnd);
		}

		if (options.isHTML()) {
			writer.println("</PRE></STRONG></FONT></BODY></HTML>");
		}

		writer.close();
	}

	private void insertUndefinedBytesRemovedMarker(Address bytesRemovedRangeStart,
			Address bytesRemovedRangeEnd) {

		writer.println();

		buffy = new StringBuilder();
		if (options.isHTML()) {
			writer.print("<FONT COLOR=#ff0000>");
		}
		processAddress(bytesRemovedRangeStart, null);
		buffy.append(" -> ");
		processAddress(bytesRemovedRangeEnd, null);
		buffy.append(" [UNDEFINED BYTES REMOVED]");
		writer.print(buffy.toString());

		if (options.isHTML()) {
			writer.print("</FONT>");
		}
		writer.println();
		writer.println();
	}

	private String toHREF(Address addr) {
		return AbstractLineDispenser.getUniqueAddressString(addr);
	}

	private String toHREF(Variable var) {
		return var.getFunction().getName() + "_" + var.getName();
	}

	private String genFill(int length) {
		return AbstractLineDispenser.getFill(length);
	}

	private String clip(String s, int len, boolean padIfShorter, boolean leftJustify) {
		return AbstractLineDispenser.clip(s, len, padIfShorter, leftJustify);
	}

	private void processVariable(Variable var) {
		buffy = new StringBuilder();

		buffy.append(genFill(options.getStackVarPreNameWidth()));

		if (options.isHTML()) {
			buffy.append(BEGIN_ANCHOR + toHREF(var) + END_ANCHOR);
		}

		String clipName = clip(options.getCommentPrefix() + var.getName(),
			options.getStackVarNameWidth() - 1, true, true);
		buffy.append(clipName);
		buffy.append(genFill(options.getStackVarNameWidth() - clipName.length()));

		String clipDataTypeName = clip(var.getDataType().getDisplayName(),
			options.getStackVarDataTypeWidth() - 1, true, true);
		buffy.append(clipDataTypeName);
		buffy.append(genFill(options.getStackVarDataTypeWidth() - clipDataTypeName.length()));

		String offsetStr = "";
		if (var.isStackVariable()) {
			int offset = var.getStackOffset();
			offsetStr =
				(offset >= 0 ? Integer.toHexString(offset) : "-" + Integer.toHexString(-offset));
		}
		else if (var.isRegisterVariable()) {
			offsetStr = var.getRegister().getName();
		}
		else {
			offsetStr = var.getVariableStorage().toString();
		}
		String clipOffset = clip(offsetStr, options.getStackVarOffsetWidth() - 1, true, false);
		buffy.append(clipOffset);
		buffy.append(genFill(options.getStackVarOffsetWidth() - clipOffset.length()));

		CommentLineDispenser cld = new CommentLineDispenser(var, options.getStackVarCommentWidth(),
			options.getStackVarPreNameWidth() + options.getStackVarNameWidth() +
				options.getStackVarDataTypeWidth() + options.getStackVarOffsetWidth(),
			options.getCommentPrefix());

		ReferenceLineDispenser xld = new ReferenceLineDispenser(var, program, options);

		//write out the first line from the dispenser
		//since it follows the other fields...
		if (cld.hasMoreLines()) {
			buffy.append(cld.getNextLine());
		}
		else {
			buffy.append(AbstractLineDispenser.getFill(cld.width));
		}
		buffy.append(" ");
		if (xld.hasMoreLines()) {
			buffy.append(xld.getNextLine());
		}

		writer.println(buffy.toString());

		while (cld.hasMoreLines() || xld.hasMoreLines()) {
			buffy = new StringBuilder();

			buffy.append(cld.getFill());
			if (cld.hasMoreLines()) {
				buffy.append(cld.getNextLine());
			}
			buffy.append(" ");
			if (xld.hasMoreLines()) {
				buffy.append(xld.getNextLine());
			}
			writer.println(buffy.toString());
		}

		cld.dispose();
		xld.dispose();
	}

	private void processAddress(Address cuAddress, String prefix) {

		if (prefix != null) {
			buffy.append(prefix);
		}

		int width = options.getAddrWidth();
		if (width < 1) {
			return;
		}

		String addrstr = cuAddress.toString();

		if (options.isShowBlockName()) {
			MemoryBlock block = memory.getBlock(cuAddress);
			if (block != null) {
				addrstr = block.getName() + ":" + addrstr;
			}
		}

		buffy.append(clip(addrstr, width, true, true));
	}

	private void addReferenceLinkedText(Reference ref, String text, boolean checkForVariable) {
		Variable var = null;
		if (ref != null && options.isHTML()) {
			var = referenceManager.getReferencedVariable(ref);
		}
		if (var == null) {
			// use alternate method for non-variable or non-HTML mode
			Address toAddr = ref != null ? ref.getToAddress() : null;
			addAddressLinkedText(toAddr, text);
			return;
		}
		buffy.append("<A HREF=\"#");
		buffy.append(toHREF(var));
		buffy.append("\">");

		buffy.append(text);

		buffy.append("</A>");
	}

	private void addAddressLinkedText(Address toAddr, String text) {
		boolean includeLink = false;
		if (toAddr != null && options.isHTML()) {
			includeLink = toAddr.isMemoryAddress() && addressSet.contains(toAddr);
		}
		if (includeLink) {
			buffy.append("<A HREF=\"#");
			buffy.append(toHREF(toAddr));
			buffy.append("\">");
		}
		buffy.append(text);
		if (includeLink) {
			buffy.append("</A>");
		}
	}

	private void processMnemonic(CodeUnit cu) {
		int width = options.getMnemonicWidth();
		if (width < 1) {
			return;
		}
		buffy.append(genFill(options.getPreMnemonicWidth()));

		String mnemonic = cu.getMnemonicString();
		String mnemonicText = clip(mnemonic, width - 1, false, true);
		if (options.isHTML()) {
			Reference primRef =
				referenceManager.getPrimaryReferenceFrom(cu.getAddress(), CodeUnit.MNEMONIC);
			addReferenceLinkedText(primRef, mnemonicText, true);
		}
		else {
			buffy.append(mnemonicText);
		}
		buffy.append(clip("", width - mnemonic.length(), true, true));
	}

	private void processBytes(CodeUnit cu) {
		int width = options.getBytesWidth();
		if (width < 1) {
			return;
		}

		try {
			byte[] bytes = cu.getBytes();
			StringBuffer bytesbuf = new StringBuffer();
			for (int i = 0; i < bytes.length; ++i) {
				if (i > 0) {
					bytesbuf.append(BYTES_DELIM);
				}
				if (bytes[i] >= 0x00 && bytes[i] <= 0x0F) {
					bytesbuf.append("0");
				}
				bytesbuf.append(Integer.toHexString(bytes[i] & 0xff));
			}
			buffy.append(clip(bytesbuf.toString(), width, true, true));
		}
		catch (MemoryAccessException mae) {
			buffy.append(clip("", width, true, true));
		}
	}

	private void processOperand(CodeUnit cu, CodeUnitFormat cuFormat) {

		int width = options.getOperandWidth();
		if (width < 1) {
			return;
		}

		Address cuAddress = cu.getMinAddress();

		if (cu instanceof Instruction) {

			Instruction inst = (Instruction) cu;

			int opCnt = inst.getNumOperands();
			int opLens = opCnt - 1; // factor-in operand separators
			if (opCnt > 0) {

				String[] opReps = new String[opCnt];
				for (int i = 0; i < opCnt; ++i) {
					opReps[i] = cuFormat.getOperandRepresentationString(cu, i);
					opLens += opReps[i].length();
				}
				boolean clipRequired = (opLens > width);

				opLens = opCnt - 1; // reset - factor-in operand separators
				for (int i = 0; i < opCnt; ++i) {
					if (i > 0) {
						buffy.append(",");
					}
					if (clipRequired) {
						opReps[i] = clip(opReps[i], (width - opLens) / (opCnt - i), false, true);
					}
					opLens += opReps[i].length();

					if (options.isHTML()) {
						Reference ref =
							cu.getProgram()
									.getReferenceManager()
									.getPrimaryReferenceFrom(cuAddress,
										i);
						addReferenceLinkedText(ref, opReps[i], true);
					}
					else {
						buffy.append(opReps[i]);
					}
				}
			}
			String fill = genFill(width - opLens);
			buffy.append(fill);
		}
		else if (cu instanceof Data) {
			Data data = (Data) cu;
			String opRep = cuFormat.getDataValueRepresentationString(data);
			String opData = clip(opRep, width, false, true);
			String fill = genFill(width - opData.length());
			Reference mr = referenceManager.getPrimaryReferenceFrom(cuAddress, 0);
			addReferenceLinkedText(mr, opData, false);
			buffy.append(fill);
		}
	}

	private void processSubData(Data data, int indentLevel, CodeUnitFormat cuFormat) {
		int componentCount = data.getNumComponents();
		for (int i = 0; i < componentCount; ++i) {
			Data component = data.getComponent(i);
			if (component == null) {
				return; // it has been changed since we retrieved the number of components
			}

			String fill = genFill(indentLevel * INDENT_SPACES);

			buffy = new StringBuilder();
			if (options.isHTML()) {
				buffy.append(BEGIN_ANCHOR + toHREF(component.getMinAddress()) + END_ANCHOR);
			}
			processAddress(component.getMinAddress(), fill + STRUCT_PREFIX);
			processDataFieldName(component);
			processMnemonic(component);
			processOperand(component, cuFormat);
			//processEOLComment();
			//processXREFs();
			writer.println(buffy.toString());

			processSubData(component, indentLevel + 1, cuFormat);
		}
	}

	private void processDataFieldName(Data data) {
		int width = options.getDataFieldNameWidth();
		if (width < 1) {
			return;
		}

		String str = clip(data.getFieldName(), width, true, true);
		buffy.append(str);
	}

	/**
	 * Move primary symbol to last element in array ...
	 */
	private void makePrimaryLastItem(Symbol[] symbols) {
		for (int i = 0; i < symbols.length - 1; ++i) {
			if (symbols[i].isPrimary()) {
				Symbol primary = symbols[i];
				System.arraycopy(symbols, i + 1, symbols, i, symbols.length - i - 1);
				symbols[symbols.length - 1] = primary;

				break;
			}
		}
	}

	private void processPlate(CodeUnit cu, String[] plate) {
		if (cu == null) {
			return;
		}
		if ((plate == null) || (plate.length == 0)) {
			return;
		}

		int x = 0, before = 2, after = 0, len = 0;
		int width = options.getPreMnemonicWidth() + options.getMnemonicWidth() +
			options.getOperandWidth() + options.getEolWidth();

		if (width == 0) {
			return;
		}

		String fill = genFill(options.getAddrWidth() + options.getBytesWidth());

		StringBuffer stars = new StringBuffer();
		for (x = 0; x < width; x++) {
			stars.append("*");
		}

		if (options.isHTML()) {
			writeComments(stars.toString(), fill);
		}
		else {
			writeComments(stars.toString(), fill);
		}

		for (String element : plate) {
			String s = clip(element, width, false, true);
			len = s.length();
			if (plate.length == 1) {
				before = (width - 2 - len) / 2;
			}
			after = width - 2 - len - before;

			String pre = genFill(before);
			String post = genFill(after);

			writeComments("*" + pre + s + post + "*", fill);
		}

		writeComments(stars.toString(), fill);
	}

	private void processSpace(int type) {
		for (int x = 0; x < type; x++) {
			buffy = new StringBuilder();
			writer.println(buffy.toString());
		}
	}

	private void writeComments(String what, String fill) {
		buffy = new StringBuilder();
		if (fill != null) {
			buffy.append(fill);
		}
		buffy.append(options.getCommentPrefix());
		buffy.append(what);
		writer.println(buffy.toString());
	}
}
