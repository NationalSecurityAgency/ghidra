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
//
//   Attempt to detect defined functions in a program that don't return.
//   Functions like exit(), abort(), bassert() don't return, and sometimes
//   compilers know this.  They will start the next function or data immediately
//   after the call to the function that is known not to return.
//   This can cause bad disassembly, incestuous functions, etc...
//
//   This script finds functions that don't return by looking at the code that
//   follows all function calls.
//   Once the no-return usage is detected, it marks the offending functions, and
//   everywhere they are called, changes the fallthru of the call.
//   Then each function that had a fixed up call, re-detect the functions body.
//
//   No code, or bad disassembly marks are cleared.
//
//   You can run this script once, and it will add bookmarks at each potential non-returning
//   function, and at each location that calls the function in a suspicious way.
//
//@category Functions

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;

public class FixupNoReturnFunctionsNoRepairScript extends FixupNoReturnFunctionsScript {

	@Override
	void repairDamage(Program cp, Function func, Address entry) {
		func.setNoReturn(true);

		try {
			String name = func.getName();
			entryList.setMessage("Clearing fallthrough for: " + name);
			setNoFallThru(cp, entry);

			entryList.setMessage("Fixup function bodies for: " + name);
			fixCallingFunctionBody(cp, entry);

			//entryList.setMessage("Clearing and repairing flows for: " + name);
			//clearAndRepairFlows(cp, entry);
		}
		catch (CancelledException e) {
			// a cancel here implies that the entire script has been cancelled
		}
	}
}
