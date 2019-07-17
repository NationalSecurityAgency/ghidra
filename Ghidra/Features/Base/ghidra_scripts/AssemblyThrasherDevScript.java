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
//Thoroughly test the assembler by attempting to assemble and match EVERY instruction code unit.
//NOTE: I do not de-duplicate, since the address of the instruction may affect the output.
//@category Assembly

import java.awt.Color;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.HashSet;
import java.util.Set;

import javax.swing.ImageIcon;

import org.apache.commons.lang3.StringUtils;

import ghidra.app.plugin.assembler.*;
import ghidra.app.plugin.assembler.sleigh.sem.*;
import ghidra.app.plugin.processors.sleigh.SleighDebugLogger;
import ghidra.app.plugin.processors.sleigh.SleighDebugLogger.SleighDebugMode;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.NumericUtilities;
import resources.ResourceManager;

public class AssemblyThrasherDevScript extends GhidraScript {
	public static final String BOOKMARK_FAIL = "AssemblyFailure";
	public static final String BOOKMARK_PASS = "AssemblySuccess";

	class Accept extends RuntimeException {
		// custom exception
	}

	class AllMatchByTextSelector extends AssemblySelector {
		private Instruction orig;
		@SuppressWarnings("unused")
		private Address addr;
		private String text;

		public void setExpected(Instruction ins) {
			this.orig = ins;
			this.addr = ins.getAddress();
			this.text = ins.toString().trim();
		}

		@Override
		public AssemblyResolvedConstructor select(AssemblyResolutionResults rr,
				AssemblyPatternBlock ctx) throws AssemblySemanticException {
			StringBuilder sb = new StringBuilder();
			boolean gotOne = false;
			boolean failedOne = false;
			for (AssemblyResolution ar : rr) {
				if (ar.isError()) {
					continue;
				}
				AssemblyResolvedConstructor can = (AssemblyResolvedConstructor) ar;
				if (can.getContext().combine(ctx) == null) {
					continue;
				}
				for (byte[] ins : can.possibleInsVals(ctx)) {
					String cantext = disassemble(orig, ins).toString().trim();
					if (cantext.equals(text)) {
						gotOne = true;
					}
					else {
						sb.append("Mismatch: " + NumericUtilities.convertBytesToString(ins) +
							" => " + cantext + ". ");
						failedOne = true;
					}
				}
			}
			if (!gotOne) {
				throw new AssemblySemanticException("No match found");
			}
			if (failedOne) {
				throw new AssemblySemanticException(sb.toString());
			}
			// Don't return, to avoid modifying the binary.
			throw new Accept();
		}
	}

	@Override
	protected void run() throws Exception {
		clearBackgroundColor(currentProgram.getMemory().getAllInitializedAddressSet());

		BookmarkManager bm = currentProgram.getBookmarkManager();
		ImageIcon myIcon = ResourceManager.loadImage("images/warning.png");
		bm.defineType(BOOKMARK_FAIL, myIcon, new Color(255, 255, 0), 0);
		bm.removeBookmarks(BOOKMARK_FAIL);

		monitor.setMessage("Constructing Assembler");
		AllMatchByTextSelector checker = new AllMatchByTextSelector();
		Assembler asm = Assemblers.getAssembler(currentProgram, checker);
		Set<String> done = new HashSet<>();
		AddressSet uniques = createAddressSet();
		for (Instruction ins : currentProgram.getListing().getInstructions(currentAddress, true)) {
			if (monitor.isCancelled()) {
				return;
			}

			SleighDebugLogger debug =
				new SleighDebugLogger(currentProgram, ins.getAddress(), SleighDebugMode.MASKS_ONLY);
			String linenos = StringUtils.join(debug.getConstructorLineNumbers(), " ");
			monitor.setMessage("Assembling " + ins.getAddress());
			if (!done.add(linenos)) {
				continue;
			}
			uniques.add(ins.getAddress());
			checker.setExpected(ins);
			try {
				asm.assemble(ins.getAddress(), ins.toString());
			}
			catch (Accept e) {
				bm.setBookmark(ins.getAddress(), BOOKMARK_PASS, "Assembly Succeeded",
					e.getMessage());
			}
			catch (AssemblySemanticException e) {
				bm.setBookmark(ins.getAddress(), BOOKMARK_FAIL, "Semantic Error", e.getMessage());
			}
			catch (AssemblySyntaxException e) {
				bm.setBookmark(ins.getAddress(), BOOKMARK_FAIL, "Syntax Error", e.getMessage());
			}
			catch (UnsupportedOperationException e) {
				ByteArrayOutputStream buf = new ByteArrayOutputStream();
				PrintStream p = new PrintStream(buf);
				e.printStackTrace(p);
				bm.setBookmark(ins.getAddress(), BOOKMARK_FAIL, "Unfinished",
					new String(buf.toByteArray()));
			}
			catch (Exception e) {
				ByteArrayOutputStream buf = new ByteArrayOutputStream();
				PrintStream p = new PrintStream(buf);
				e.printStackTrace(p);
				bm.setBookmark(ins.getAddress(), BOOKMARK_FAIL, "Severe Error",
					new String(buf.toByteArray()));
			}
		}

		println("Unique instructions by constructor: " + done.size());
		setBackgroundColor(uniques, new Color(255, 128, 128));
	}

	protected PseudoInstruction disassemble(Instruction orig, byte[] ins) {
		try {
			Address at = orig.getAddress();
			Language language = currentProgram.getLanguage();
			MemBuffer buf = new ByteMemBufferImpl(at, ins, language.isBigEndian());
			InstructionPrototype ip = language.parse(buf, orig, false);
			return new PseudoInstruction(at, ip, buf, orig);
		}
		catch (InsufficientBytesException | UnknownInstructionException
				| AddressOverflowException e) {
			throw new RuntimeException(e);
		}
	}
}
