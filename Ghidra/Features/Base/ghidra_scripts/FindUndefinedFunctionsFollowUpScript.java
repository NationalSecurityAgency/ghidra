/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
// The Ghidra FindUndefinedFunctionsScript.java script will often incorrectly
// identify function entry points.  This script attempts to find and fix
// those bad entry points.
//
// <b>Issues</b>:  Memory bounds checking is hard-coded. It incorrectly identifies random 
//          0x60000000 values that the compiler inserted between some functions 
//          as "ori r0,r0,0" instructions that should be added to the head of the 
//          functions those values precede.  It makes assumptions that wouldn't be helpful in 
//          an image that hasn't been mostly disassembled already.  I'm sure there are other 
//          problems with it.  Still, it did a pretty good job of cleaning up after 
//          FindUndefinedFunctionsScript.
//
//@category CustomerSubmission.Analysis.Repair

import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;

public class FindUndefinedFunctionsFollowUpScript extends GhidraScript {

	@Override
	public void run() throws Exception {

		FunctionIterator funcs = currentProgram.getListing().getFunctions(true);
		Memory mem = currentProgram.getMemory();
		int count = 0;

		while (funcs.hasNext() && !monitor.isCancelled()) {

			Function f = funcs.next();
			Address a = f.getEntryPoint();

			// auto func: starts with "FUN_" and 1st instr is "mfspr r0,LR"
			if (f.getName().startsWith("FUN_") && mem.getInt(a) == 0x7c0802a6) {

				// does func have a few undefined intstructions before it?
				// if so, get frag start address, disassemble frag, remove
				// the defined function, and create a new function at start
				// of frag
				Address fsa = findFrag(a);
				if (fsa != null) {
					disassemble(fsa);
					removeFunction(f);
					String fname = Long.toHexString(fsa.getOffset());
					int i;
					for (i = fname.length(); i < 8; i++)
						fname = "0" + fname;
					fname = "FUN_" + fname;
					createFunction(fsa, fname);
					println("fixed func at 0x" + Long.toHexString(fsa.getOffset()));
					count = count + 1;
				}
				else {
					// does func have a few defined instructions before it
					// that don't include "b" or "blr" and start with an
					// instruction defined as the start of a function?
					// if so then delete function at current address, delete
					// function defined at start of head, and recreate function
					// at start of head (to include what was in function
					// formerly defined at current address)
					Address head = findHead(a);
					if (head != null) {
						removeFunction(f);
						f = getFunctionAt(head);
						String fname = f.getName();
						removeFunction(f);
						createFunction(head, fname);
						println("fixed func at 0x" + Long.toHexString(head.getOffset()));
						count = count + 1;
					}
				}
			}

		}

		println("Fixed " + count + " functions.");

	}

	private Address findFrag(Address a) throws Exception {
		// looking for something like this:
		//    01e328e4   r3 80 00 20   blr           // end of prev func
		//    01e328e8   94            ??       94h
		//    01e328e9   21            ??       21h
		//    01e328ea   ff            ??       FFh
		//    01e328eb   e0            ??       E0h
		//    01e328ec   2c            ??       2Ch
		//    01e328ed   03            ??       03h
		//    01e328ee   00            ??       00h
		//    01e328ef   00            ??       00h
		//                  undefined FUN_01e328f0   // <-- Address a
		//    01e328f0   7c 08 02 a6   mfspr    r0,LR
		//    01e328f4   39 80 00 31   li       r12,0x31
		//    ...
		//
		// if there are 1-6 undefined instructions before Address a and
		// a "b" or "blr" instruction before that, then return the address
		// of the dword following the "b" or "blr" instruction -- else
		// return null

		Memory mem = currentProgram.getMemory();

		// save start address before we start scanning backward
		Address sa = a;
		Listing listing = currentProgram.getListing();

		// memory bounds checking is hard-coded -- yes...bad
		// try to find up to 6 undefined instructions before start address
		while (a.getOffset() > 0x1800000 && sa.getOffset() - a.getOffset() < 24 &&
			listing.isUndefined(a.subtract(4), a.subtract(1)) && isInstruction(a.subtract(4))) {
			if (monitor.isCancelled())
				return (null);
			a = a.subtract(4);
		}

		// if the dword we are pointing to isn't undefined, we didn't find frag
		if (!listing.isUndefined(a, a.add(3)))
			return (null);

		// if we didn't find an instruction, then we didn't find a frag
		if (listing.getInstructionAt(a.subtract(4)) == null)
			return (null);

		// if instruction isn't a "b" and isn't a "blr", we didn't find a frag
		int val = mem.getInt(a.subtract(4));
		if ((val & 0xfc000000) != 0x48000000 && val != 0x4e800020)
			return (null);

		// at this point, assume that we found a frag, starting at a
		return (a);
	}

	private boolean isInstruction(Address a) {
		// is undefined dword at specified address a valid instruction?

		PseudoDisassembler pdis = new PseudoDisassembler(currentProgram);
		PseudoInstruction pi = null;

		try {
			pi = pdis.disassemble(a);
		}
		catch (InsufficientBytesException e) {
			println("insufficient bytes at " + Long.toHexString(a.getOffset()));
			return (false);
		}
		catch (UnknownInstructionException e) {
			println("unknown instr at " + Long.toHexString(a.getOffset()));
		}
		catch (UnknownContextException e) {
			println("unknown context at " + Long.toHexString(a.getOffset()));
		}

		if (pi == null)
			return (false);

		return (true);
	}

	private Address findHead(Address a) throws Exception {
		// looking for something like this:
		//                  undefined FUN_01e328e8
		//    01e328e8   94 21 ff e0   stwu     r1,-0x20(r1)
		//    01e328ec   2c 03 00 00   cmpwi    r3,0x0
		//                  undefined FUN_01e328f0   // <-- Address a
		//    01e328f0   7c 08 02 a6   mfspr    r0,LR
		//    01e328f4   39 80 00 31   li       r12,0x31
		//    ...
		// if there are 1-6 defined instructions before Address a, none
		// of them are "b" or "blr", and the first one is defined as the
		// start of a function, then return the address defined as the
		// start of a function -- else return null

		Memory mem = currentProgram.getMemory();

		// save start address before we start scanning backward
		Address sa = a;
		Listing listing = currentProgram.getListing();

		// memory bounds checking is hard-coded -- yes...bad
		// try to find up to 6 instructions before start address that don't
		// include "b" or "blr" and start with instruction defined as start
		// of function
		int val = mem.getInt(a.subtract(4));
		while (a.getOffset() > 0x1800000 && sa.getOffset() - a.getOffset() < 24 &&
			listing.getInstructionAt(a.subtract(4)) != null &&
			((val & 0xfc000000) != 0x48000000 && val != 0x4e800020) &&
			listing.getFunctionAt(a.subtract(4)) == null) {
			if (monitor.isCancelled())
				return (null);
			a = a.subtract(4);
			val = mem.getInt(a.subtract(4));
		}

		// if we found a "b" or "blr", we didn't find a function header
		if ((val & 0xfc000000) == 0x48000000 || val == 0x4e800020)
			return (null);

		// if the instruction before the one we are pointing to isn't
		// a function entry point, we didn't find a function header
		if (listing.getFunctionAt(a.subtract(4)) == null)
			return (null);

		// at this point, assume that we found a function header, starting at a-4
		return (a.subtract(4));
	}

}
