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
package ghidra.app.util.bin.format.objc;

import java.io.Closeable;
import java.util.*;

import ghidra.app.util.bin.format.macho.dyld.LibObjcOptimization;
import ghidra.app.util.bin.format.objc.objc1.Objc1TypeEncodings;
import ghidra.app.util.bin.format.objc.objc2.Objc2Class;
import ghidra.app.util.bin.format.objc.objc2.Objc2InstanceVariable;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.listing.Program;

public class ObjcState implements Closeable {

	/**
	 * If an index is contained in this set, then the corresponding data structure has been applied 
	 * to the program.
	 */
	public final Set<Long> beenApplied = new HashSet<Long>();

	/**
	 * A map of method addresses to mangled signature strings.
	 */
	public final Map<Address, ObjcMethod> methodMap = new HashMap<Address, ObjcMethod>();

	/**
	 * If an address is contained in this set, then it is thumb code.
	 */
	public final Set<Address> thumbCodeLocations = new HashSet<Address>();

	/**
	 * A map of the index where the class structure was defined to instantiated class object.
	 */
	public final Map<Long, Objc2Class> classIndexMap = new HashMap<Long, Objc2Class>();

	/**
	 * A map of instance variable addresses to mangled type strings.
	 */
	public final Map<Address, Objc2InstanceVariable> variableMap =
		new HashMap<Address, Objc2InstanceVariable>();

	/**
	 * The dyld_shared_cache libobjc objc_opt_t structure, if it exists
	 */
	public LibObjcOptimization libObjcOptimization = null;

	public final Objc1TypeEncodings encodings;

	public ObjcState(Program program, CategoryPath categoryPath) {
		this.encodings = new Objc1TypeEncodings(program.getDefaultPointerSize(), categoryPath);
	}

	@Override
	public void close() {
		beenApplied.clear();
		methodMap.clear();
		thumbCodeLocations.clear();
	}
}
