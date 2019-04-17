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
package ghidra.app.util;

import java.util.*;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

/**
 * A utility class to handle the generation of
 * direct and offcut cross-reference (XREF) lists
 * on code units and stack variables.
 */
public class XReferenceUtil {
	private final static Address[] EMPTY_ADDR_ARRAY = new Address[0];
	private final static Reference[] EMPTY_REF_ARRAY = new Reference[0];

	// Methods in this class treat -1 as a key to return all references and
	// not cap the result set.
	public final static int ALL_REFS = -1;

	/**
	 * Returns an array containing all
	 * direct XREF addresses to the specified code unit.
	 * 
	 * @param cu the code unit to generate the XREFs
	 * 
	 * @return array of all XREFs to the code unit
	 */
	public final static Address[] getXRefList(CodeUnit cu) {
		return getXRefList(cu, -1); // get all 
	}

	/**
	 * Returns an array containing the first <b><code>maxNumber</code></b>
	 * direct XREF addresses to the specified code unit.
	 *  
	 * @param cu the code unit to generate the XREFs
	 * @param maxNumber max number of XREFs to get,
	 *                  or -1 to get all references
	 *  
	 * @return array first <b><code>maxNumber</code></b> XREFs to the code unit
	 */
	public final static Address[] getXRefList(CodeUnit cu, int maxNumber) {
		Program prog = cu.getProgram();
		if (prog == null) {
			return EMPTY_ADDR_ARRAY;
		}
		List<Address> xrefList = new ArrayList<Address>();
		//lookup the direct XREFs to the current code unit
		//
		ReferenceIterator iter = prog.getReferenceManager().getReferencesTo(cu.getMinAddress());
		while (iter.hasNext()) {
			Reference ref = iter.next();
			xrefList.add(ref.getFromAddress());
			if (maxNumber > 0 && xrefList.size() == maxNumber) {
				break;
			}
		}
		Address[] arr = new Address[xrefList.size()];
		xrefList.toArray(arr);
		Arrays.sort(arr);
		return arr;
	}

	/**
	 * Returns an array containing the first <b><code>maxNumber</code></b>
	 * direct XREF references to the specified code unit.
	 *  
	 * @param cu the code unit to generate the XREFs
	 * @param maxNumber max number of XREFs to get,
	 *                  or -1 to get all references
	 *  
	 * @return array first <b><code>maxNumber</code></b> XREFs to the code unit
	 */
	public final static Reference[] getXReferences(CodeUnit cu, int maxNumber) {
		Program prog = cu.getProgram();
		if (prog == null) {
			return EMPTY_REF_ARRAY;
		}
		List<Reference> xrefList = new ArrayList<Reference>();
		//lookup the direct XREFs to the current code unit
		//
		ReferenceIterator iter = prog.getReferenceManager().getReferencesTo(cu.getMinAddress());
		while (iter.hasNext()) {
			Reference ref = iter.next();
			xrefList.add(ref);
			if (maxNumber > 0 && xrefList.size() == maxNumber) {
				break;
			}
		}
		// Check for thunk reference
		Function func = prog.getFunctionManager().getFunctionAt(cu.getMinAddress());
		if (func != null) {
			Address[] thunkAddrs = func.getFunctionThunkAddresses();
			if (thunkAddrs != null) {
				for (Address thunkAddr : thunkAddrs) {
					xrefList.add(new ThunkReference(thunkAddr, func.getEntryPoint()));
				}
			}
		}
		Reference[] arr = new Reference[xrefList.size()];
		xrefList.toArray(arr);
		return arr;
	}

	/**
	 * Returns an array containing all
	 * offcut XREF addresses to the specified code unit.
	 * 
	 * @param cu the code unit to generate the offcut XREFs
	 * 
	 * @return array of all offcut XREFs to the code unit
	 */
	public final static Address[] getOffcutXRefList(CodeUnit cu) {
		return getOffcutXRefList(cu, -1); // get all
	}

	/**
	 * Returns an array containing all
	 * offcut XREF addresses to the specified code unit.
	 * 
	 * @param cu the code unit to generate the offcut XREFs
	 * @param maxXRefs max number of offcut XREFs to get,
	 *                  or -1 to get all offcut references
	 * 
	 * @return array of all offcut XREFs to the code unit
	 */
	public final static Address[] getOffcutXRefList(CodeUnit cu, int maxXRefs) {
		Program prog = cu.getProgram();
		if (prog == null) {
			return EMPTY_ADDR_ARRAY;
		}
		List<Address> offcutList = new ArrayList<Address>();
		// Lookup the offcut XREFs...
		//
		if (cu.getLength() > 1) {
			ReferenceManager refMgr = prog.getReferenceManager();
			AddressSet set =
				new AddressSet(cu.getMinAddress().add(1), cu.getMaxAddress());
			AddressIterator iter = refMgr.getReferenceDestinationIterator(set, true);
			while (iter.hasNext()) {
				Address addr = iter.next();
				ReferenceIterator refIter = refMgr.getReferencesTo(addr);
				while (refIter.hasNext()) {
					Reference ref = refIter.next();
					offcutList.add(ref.getFromAddress());
					if (maxXRefs > 0 && offcutList.size() == maxXRefs) {
						break;
					}
				}
			}
		}
		Address[] arr = new Address[offcutList.size()];
		offcutList.toArray(arr);
		Arrays.sort(arr);
		return arr;
	}

	/**
	 * Returns an array containing all
	 * offcut XREF references to the specified code unit.
	 * 
	 * @param cu the code unit to generate the offcut XREFs
	 * @param maxXRefs max number of offcut XREFs to get,
	 *                  or -1 to get all offcut references
	 * 
	 * @return array of all offcut XREFs to the code unit
	 */
	public final static Reference[] getOffcutXReferences(CodeUnit cu, int maxXRefs) {
		Program prog = cu.getProgram();
		if (prog == null) {
			return EMPTY_REF_ARRAY;
		}
		List<Reference> offcutList = new ArrayList<Reference>();
		// Lookup the offcut XREFs...
		//
		if (cu.getLength() > 1) {
			ReferenceManager refMgr = prog.getReferenceManager();
			AddressSet set =
				new AddressSet(cu.getMinAddress().add(1), cu.getMaxAddress());
			AddressIterator iter = refMgr.getReferenceDestinationIterator(set, true);
			while (iter.hasNext()) {
				Address addr = iter.next();
				ReferenceIterator refIter = refMgr.getReferencesTo(addr);
				while (refIter.hasNext()) {
					Reference ref = refIter.next();
					offcutList.add(ref);
					if (maxXRefs > 0 && offcutList.size() == maxXRefs) {
						break;
					}
				}
			}
		}
		Reference[] arr = new Reference[offcutList.size()];
		offcutList.toArray(arr);
		Arrays.sort(arr);
		return arr;
	}

	/**
	 * Returns the count of all 
	 * offcut XREF addresses to the specified code unit.
	 * @param cu the code unit to generate the offcut XREFs
	 * @return count of all offcut XREFs to the code unit
	 */
	public static int getOffcutXRefCount(CodeUnit cu) {
		Program prog = cu.getProgram();
		if (prog == null) {
			return 0;
		}
		int refCount = 0;
		if (cu.getLength() > 1) {
			ReferenceManager refMgr = prog.getReferenceManager();
			AddressSet set =
				new AddressSet(cu.getMinAddress().add(1), cu.getMaxAddress());
			AddressIterator iter = refMgr.getReferenceDestinationIterator(set, true);
			while (iter.hasNext()) {
				Address addr = iter.next();
				ReferenceIterator refIter = refMgr.getReferencesTo(addr);
				while (refIter.hasNext()) {
					refIter.next();
					++refCount;
				}
			}
		}
		return refCount;
	}

	/**
	 * Populates the provided array lists with the direct and
	 * offcut XREFs to the specified variable.
	 * 
	 * @param var     variable to get references
	 * @param xrefs   list to put direct references on
	 * @param offcuts list to put offcut references on
	 */
	public static void getVariableRefs(Variable var, List<Reference> xrefs, List<Reference> offcuts) {
		Address addr = var.getMinAddress();
		if (addr == null) {
			return;
		}
		Program program = var.getFunction().getProgram();
		ReferenceManager refMgr = program.getReferenceManager();
		Reference[] vrefs = refMgr.getReferencesTo(var);
		for (Reference vref : vrefs) {
			if (addr.equals(vref.getToAddress())) {
				xrefs.add(vref);
			}
			else {
				offcuts.add(vref);
			}
		}
	}

	/**
	 * Get the reference count to the min address of the given code unit.
	 * If an external entry exists there, then subtract one from the count.
	 * @param cu code unit
	 * @return reference count, excluding an external entry reference
	 */
	public static int getReferenceCount(CodeUnit cu) {
		Program program = cu.getProgram();
		Address toAddr = cu.getMinAddress();
		int count = program.getReferenceManager().getReferenceCountTo(toAddr);
		if (program.getSymbolTable().isExternalEntryPoint(toAddr)) {
			--count;
		}
		return count;
	}
}
