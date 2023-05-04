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
package ghidra.app.util.bin.format.dwarf4.funcfixup;

import java.util.List;

import ghidra.app.util.bin.format.dwarf4.DWARFException;
import ghidra.app.util.bin.format.dwarf4.next.DWARFFunction;
import ghidra.program.model.listing.Function;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.classfinder.ExtensionPoint;

/**
 * Interface for add-in logic to fix/modify/tweak DWARF functions before they are written 
 * to the Ghidra program.
 * <p>
 * Use {@code @ExtensionPointProperties(priority = DWARFFunctionFixup.PRIORITY_*)} to
 * control the order of evaluation (higher numbers are run earlier).
 * <p>
 * Fixups are found using {@link ClassSearcher}, and their class names must end
 * in "DWARFFunctionFixup" (see ExtensionPoint.manifest). 
 */
public interface DWARFFunctionFixup extends ExtensionPoint {
	public static final int PRIORITY_NORMAL_EARLY = 4000;
	public static final int PRIORITY_NORMAL = 3000;
	public static final int PRIORITY_NORMAL_LATE = 2000;
	public static final int PRIORITY_LAST = 1000;

	/**
	 * Called before a {@link DWARFFunction} is used to create a Ghidra Function.
	 * <p>
	 * If processing of the function should terminate (and the function be skipped), throw
	 * a {@link DWARFException}.
	 *  
	 * @param dfunc {@link DWARFFunction} info read from DWARF about the function
	 * @param gfunc the Ghidra {@link Function} that will receive the DWARF information
	 */
	void fixupDWARFFunction(DWARFFunction dfunc, Function gfunc) throws DWARFException;

	/**
	 * Return a list of all current {@link DWARFFunctionFixup fixups} found in the classpath
	 * by ClassSearcher.
	 * 
	 * @return list of all current fixups found in the classpath
	 */
	public static List<DWARFFunctionFixup> findFixups() {
		return ClassSearcher.getInstances(DWARFFunctionFixup.class);
	}

}
