/* ###
 * IP: GHIDRA
 * REVIEWED: YES
 * NOTE: Is this needed anymore?
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
// Sets function to have varArgs wherever a function's entry point address has a "decompiler_tags"
// property containing "<dotdotdot/>". It then removes the dotdotdot tag from the decompiler_tags.
// If the decompiler tags is then empty, it is also removed.
// Currently this doesn't remove the dotdotdot tag if there isn't a function at that address in the program.
//@category Update

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.program.model.util.StringPropertyMap;

public class ConvertDotDotDotScript extends GhidraScript {
	
	long numDots;
	long numEmpty;

    @Override
    public void run() throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();
		PropertyMapManager pm = currentProgram.getUsrPropertyManager();
		StringPropertyMap stringmap = pm.getStringPropertyMap(HighFunction.DECOMPILER_TAG_MAP);
		if (stringmap == null) {
    		println("Your program doesn't have any DotDotDot tags to convert.");
			return;
		}
		numDots = 0;
		numEmpty = 0;
		AddressIterator iter = stringmap.getPropertyIterator();
		while (iter.hasNext()) {
			Address addr = iter.next();
			Function f = fm.getFunctionAt(addr);
			if (f == null) {
				continue;
			}
			if (hasDotDotDotTag(stringmap, addr)) {
				if (!f.hasVarArgs()) {
					f.setVarArgs(true);
					println("Function "+f.getName()+" at "+addr.toString()+" now has varargs.");
				}
				removeDotDotDotTag(stringmap, addr);
			}
			else {
				if (removeEmptyTag(stringmap, addr)) {
				}
			}
		}
		println("Removed total of "+numDots+" dotdotdot tag"+((numDots!=1)?"s":"")+".");
		println("Removed total of "+numEmpty+" empty "+HighFunction.DECOMPILER_TAG_MAP+
				" propert"+((numEmpty!=1)?"ies":"y")+".");
    }

	private boolean hasDotDotDotTag(StringPropertyMap stringmap, Address addr) {
		String funcstring = stringmap.getString(addr);
		return funcstring.indexOf("<dotdotdot/>") != -1;
	}

	private void removeDotDotDotTag(StringPropertyMap stringmap, Address addr) {
		String funcString = stringmap.getString(addr);
		if (funcString == null) {
			return;
		}
		String dotString = "<dotdotdot/>";
		int start = funcString.indexOf(dotString);
		if (start >= 0) {
			String prefix = funcString.substring(0, start);
			String suffix = "";
			try {
				suffix = funcString.substring(start+dotString.length());
			} catch (IndexOutOfBoundsException e) {
			}
			String newString = prefix + suffix;
			if (newString.length() != 0) {
				stringmap.add(addr, newString);
				println("Removed dotdotdot tag " + " from " +
						HighFunction.DECOMPILER_TAG_MAP + " property at " + addr.toString() + ".");
			}
			else {
				stringmap.remove(addr);
				println("Removed " + HighFunction.DECOMPILER_TAG_MAP +
						" property at " + addr.toString() + " since it is now empty after removing dotdotdot tag.");
			}
			numDots++;
		}
	}

	private boolean removeEmptyTag(StringPropertyMap stringmap, Address addr) {
		String currentString = stringmap.getString(addr);
		if (currentString != null && currentString.length() == 0) {
			stringmap.remove(addr);
			println("Removed " + HighFunction.DECOMPILER_TAG_MAP +
					" property at " + addr.toString() + " since it is empty.");
			numEmpty++;
			return true;
		}
		return false;
	}

}
