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
// Compare Sliegh disassembly with external disassembly results

import java.util.HashMap;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.app.util.disassemble.GNUExternalDisassembler;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.exception.CancelledException;

public class CompareSleighExternal extends GhidraScript {

	@Override
	public void run() throws Exception {
		if (currentProgram == null) {
			return;
		}
		AddressSetView set = currentSelection;
		if (set == null || set.isEmpty()) {
			set = currentProgram.getMemory().getLoadedAndInitializedAddressSet();
		}
			
		putEquivalent("xzr", "x31");  // Think they messed up and allowed x31, there is no x31
		putEquivalent("wzr", "w31");  // Think they messed up and allowed w31, there is no w31
		putEquivalent("r12", "ip");
		
		int completed = 0;
		monitor.initialize(set.getNumAddresses());

		AddressIterator addresses = set.getAddresses(true);
		
		PseudoDisassembler pseudoDisassembler = new PseudoDisassembler(currentProgram);

		GNUExternalDisassembler dis = new GNUExternalDisassembler();
		
		long align = currentProgram.getLanguage().getInstructionAlignment();
		while (addresses.hasNext()) {
			monitor.checkCanceled();
			Address addr = addresses.next();
			
			completed++;
			
			// only on valid boundaries
			if ((addr.getOffset() % align) != 0) {
				continue;
			}
			clearBad(addr);

			monitor.setProgress(completed);

			CodeUnit cu = currentProgram.getListing().getCodeUnitAt(addr);
			if (cu == null) {
				continue;
			}
			String str = dis.getDisassembly(cu);
			
			str = str.toLowerCase();
			
			PseudoInstruction pinst = null;
			try {
				pinst = pseudoDisassembler.disassemble(addr);
			} catch (UnknownInstructionException e) {
				// didn't get an instruction, did external not get one?
				if (str.startsWith(".inst") && str.endsWith("undefined")) {
					continue;
				}
				markErrorBad(addr,"Unimplemented Instruction", str);
				continue;
			}
			// didn't get an instruction, did external not get one?
			if (pinst == null && str.startsWith(".inst") && str.endsWith("undefined")) {
				continue;
			}
			
			if (pinst == null) {
				markErrorBad(addr,"Unimplemented Instruction", str);
				continue;
			}
			
			// collapse both instruction to strings, compare removing whitespace, and to-lower
			String pStr = pinst.toString().toLowerCase().replaceAll("\\s","");
			String eStr = str.toLowerCase().replaceAll("\\s", "");
			
			// simple equivalence
			if (pStr.equals(eStr)) {
				continue;
			}
			
			String mnemonic = pinst.getMnemonicString().toLowerCase();
			if (!str.startsWith(mnemonic)) {
				markBad(addr,"Mnemonic Disagreement", str + " != " + mnemonic);
				continue;
			}
			
			int start = str.indexOf(" ");

			for (int opIndex = 0; opIndex < pinst.getNumOperands(); opIndex++) {
				// try to parse the operand string from the instruction
				int sepEnd = str.indexOf(",", start);
				
				String extOp = getExtOpStr(str, start, sepEnd);
				start = sepEnd + 1;
				
				String valStr = null;
				
				// TODO: could remove all characters, making sure none are left!
				int loc = 0;
				boolean subRegList = false;
				List<Object> opObjList = pinst.getDefaultOperandRepresentationList(opIndex);
				for (Object object : opObjList) {
					if (object instanceof Character) {
						Character ch = (Character) object;
						ch = Character.toLowerCase(ch);
						loc = extOp.indexOf(ch);
						if (loc != -1) {
							extOp = extOp.substring(0,loc) + extOp.substring(loc+1);
							continue;
						}
						if (ch.equals(',')) {
							if (subRegList) {
								continue;
							}
							// gotta move into next string, must be embedded comma
							sepEnd = str.indexOf(",", start);
							
							extOp = getExtOpStr(str, start, sepEnd);
							start = sepEnd + 1;
							continue;
						}
						if (ch.equals(' ')) {
							continue;
						}
						markBad(addr,"Missing String Markup", ch.toString());
						break;
					}
					if (object instanceof Scalar) {
						// find the scalar, hex or decimal
						Scalar scalar = (Scalar) object;
						valStr = scalar.toString(16, false, false, "0x", "");
						loc = extOp.indexOf(valStr);
						if (loc != -1) {
							extOp = extOp.substring(0,loc) + extOp.substring(loc+valStr.length());
							continue;
						}
						valStr = scalar.toString(16, true, false, "0x", "");
						loc = extOp.indexOf(valStr);
						if (loc != -1) {
							extOp = extOp.substring(0,loc) + extOp.substring(loc+valStr.length());
							continue;
						}
						valStr = scalar.toString(10, false, true, "", "");
						loc = extOp.indexOf(valStr);
						if (loc != -1) {
							extOp = extOp.substring(0,loc) + extOp.substring(loc+valStr.length());
							continue;
						}
						valStr = scalar.toString(10, false, false, "", "");
						loc = extOp.indexOf(valStr);
						if (loc != -1) {
							extOp = extOp.substring(0,loc) + extOp.substring(loc+valStr.length());
							continue;
						}
						valStr = scalar.toString(16, false, false, "", "");
						loc = extOp.indexOf(valStr);
						if (loc != -1) {
							extOp = extOp.substring(0,loc) + extOp.substring(loc+valStr.length());
							continue;
						}
						valStr = scalar.toString(16, true, false, "", "");
						loc = extOp.indexOf(valStr);
						if (loc != -1) {
							extOp = extOp.substring(0,loc) + extOp.substring(loc+valStr.length());
							continue;
						}
						markBad(addr,"Missing Scalar", valStr);
						break;
					}
					if (object instanceof Register) {
						Register reg = (Register) object;
						loc = extOp.indexOf(reg.getName().toLowerCase());
						if (loc != -1) {
							// check for '-' first
							if (extOp.charAt(0) == '-') {
								extOp = extOp.substring(1);
								loc = 0;
								subRegList = false;
							}
							extOp = extOp.substring(0,loc) + extOp.substring(loc+reg.getName().length());
							if (extOp.length() > 0 && extOp.charAt(0) == '-') {
								subRegList = true;
							}
							continue;
						}
						
						// check for equivalent register
						String equivReg = regGetEquivalent(reg.getName());
						if (equivReg != null) { 
							loc = extOp.indexOf(equivReg);
							if (loc != -1) {
								extOp = extOp.substring(0,loc) + extOp.substring(loc+equivReg.length());
								continue;
							}
						}
						
						loc = extOp.indexOf('-'); // could be a register list, assume we will find beginning and end register
						if (loc != -1) {
							continue;
						}
						markBad(addr,"Missing Register", reg.toString());
						break;
					}
					if (object instanceof Address) {
						Address dest = (Address) object;
						valStr = dest.toString(false,true);
						valStr = "0x" + valStr;
						loc = extOp.indexOf(valStr);
						if (loc != -1) {
							extOp = extOp.substring(0,loc) + extOp.substring(loc+valStr.length());
							continue;
						}
						valStr = dest.toString(false,false);
						valStr = "0x" + valStr;
						loc = extOp.indexOf(valStr);
						if (loc != -1) {
							extOp = extOp.substring(0,loc) + extOp.substring(loc+valStr.length());
							continue;
						}
						valStr = dest.toString(false,true);
						loc = extOp.indexOf(valStr);
						if (loc != -1) {
							extOp = extOp.substring(0,loc) + extOp.substring(loc+valStr.length());
							continue;
						}
						valStr = dest.toString(false,false);
						loc = extOp.indexOf(valStr);
						if (loc != -1) {
							extOp = extOp.substring(0,loc) + extOp.substring(loc+valStr.length());
							continue;
						}
						markBad(addr,"Missing Address", dest.toString());
					}
				}
				extOp = extOp.trim();
				if (extOp.length() > 0 && !extOp.startsWith(";") && !extOp.startsWith("//") && !extOp.equals("#") && !extOp.matches("[0x]+")) {
					markBad(addr,"Missing characters", extOp);
				}
			}
		}

	}

	HashMap<String, String> equivRegisters = new HashMap<String, String>();
	
	private String regGetEquivalent(String name) {
		return equivRegisters.get(name);
	}
	
	private void putEquivalent(String name, String equiv) {
		equivRegisters.put(name,  equiv);
	}

	private String getExtOpStr(String str, int start, int sepEnd) {
		String opS = null;
		if (start == -1) {
			return "";
		}
		if (sepEnd == -1) {
			opS = str.substring(start);
		} else {
			opS = str.substring(start, sepEnd);
		}
		String extOp = opS.trim();
		return extOp;
	}

	private void markBad(Address addr, String type, String error) {
		currentProgram.getBookmarkManager().setBookmark(addr, BookmarkType.WARNING,
			type,
			error);
	}
	
	private void markErrorBad(Address addr, String type, String error) {
		currentProgram.getBookmarkManager().setBookmark(addr, BookmarkType.ERROR,
			Disassembler.ERROR_BOOKMARK_CATEGORY,
			error);
	}
	
	private void clearBad(Address addr) {
		AddressSet set = new AddressSet(addr);
		try {
			currentProgram.getBookmarkManager().removeBookmarks(set, BookmarkType.WARNING, monitor);
			currentProgram.getBookmarkManager().removeBookmarks(set, BookmarkType.ERROR, monitor);
		} catch (CancelledException e) {
			// do nothing
		}
	}
}
