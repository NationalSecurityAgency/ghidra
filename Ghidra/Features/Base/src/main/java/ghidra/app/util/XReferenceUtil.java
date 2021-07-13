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

import org.apache.commons.collections4.CollectionUtils;

import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.core.table.TableComponentProvider;
import ghidra.app.util.query.TableService;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.table.ReferencesFromTableModel;
import ghidra.util.table.field.ReferenceEndpoint;

/**
 * A utility class to handle the generation of direct and offcut cross-reference (xref) lists
 * on code units and stack variables.
 * 
 * @deprecated deprecated for 10.1; removal for 10.3 or later
 */
@Deprecated // Use XReferenceUtils instead
public class XReferenceUtil {
	private final static Address[] EMPTY_ADDR_ARRAY = new Address[0];
	private final static Reference[] EMPTY_REF_ARRAY = new Reference[0];

	// Methods in this class treat -1 as a key to return all references and
	// not cap the result set.
	public final static int ALL_REFS = -1;

	/**
	 * Returns an array containing all
	 * direct xref addresses to the specified code unit.
	 * 
	 * @param cu the code unit to generate the xrefs
	 * 
	 * @return array of all xrefs to the code unit
	 */
	public final static Address[] getXRefList(CodeUnit cu) {
		return getXRefList(cu, -1); // get all 
	}

	/**
	 * Returns an array containing the first <b><code>maxNumber</code></b>
	 * direct xref addresses to the specified code unit.
	 * 
	 * @param cu the code unit to generate the xrefs
	 * @param maxNumber max number of xrefs to get,
	 *                  or -1 to get all references
	 * 
	 * @return array first <b><code>maxNumber</code></b> xrefs to the code unit
	 */
	public final static Address[] getXRefList(CodeUnit cu, int maxNumber) {
		Program prog = cu.getProgram();
		if (prog == null) {
			return EMPTY_ADDR_ARRAY;
		}
		List<Address> xrefList = new ArrayList<>();
		// lookup the direct xrefs to the current code unit
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
	 * direct xref references to the specified code unit.
	 * 
	 * @param cu the code unit to generate the xrefs
	 * @param maxNumber max number of xrefs to get,
	 *                  or -1 to get all references
	 * 
	 * @return array first <b><code>maxNumber</code></b> xrefs to the code unit
	 */
	public final static Reference[] getXReferences(CodeUnit cu, int maxNumber) {
		Program prog = cu.getProgram();
		if (prog == null) {
			return EMPTY_REF_ARRAY;
		}
		List<Reference> xrefList = new ArrayList<>();
		//lookup the direct xrefs to the current code unit
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
	 * offcut xref addresses to the specified code unit.
	 * 
	 * @param cu the code unit to generate the offcut xrefs
	 * 
	 * @return array of all offcut xrefs to the code unit
	 */
	public final static Address[] getOffcutXRefList(CodeUnit cu) {
		return getOffcutXRefList(cu, -1); // get all
	}

	/**
	 * Returns an array containing all
	 * offcut xref addresses to the specified code unit.
	 * 
	 * @param cu the code unit to generate the offcut xrefs
	 * @param maxXRefs max number of offcut xrefs to get,
	 *                  or -1 to get all offcut references
	 * 
	 * @return array of all offcut xrefs to the code unit
	 */
	public final static Address[] getOffcutXRefList(CodeUnit cu, int maxXRefs) {
		Program prog = cu.getProgram();
		if (prog == null) {
			return EMPTY_ADDR_ARRAY;
		}
		List<Address> offcutList = new ArrayList<>();
		// Lookup the offcut xrefs...
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
	 * Returns an array containing all offcut xref references to the specified code unit
	 * 
	 * @param cu the code unit to generate the offcut xrefs
	 * @param maxXRefs max number of offcut xrefs to get, or -1 to get all offcut references
	 * 
	 * @return array of all offcut xrefs to the code unit
	 */
	public final static Reference[] getOffcutXReferences(CodeUnit cu, int maxXRefs) {
		Program prog = cu.getProgram();
		if (prog == null) {
			return EMPTY_REF_ARRAY;
		}
		List<Reference> offcutList = new ArrayList<>();
		// Lookup the offcut xrefs...
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
	 * Returns the count of all offcut xref addresses to the specified code unit
	 * @param cu the code unit to generate the offcut xrefs
	 * @return count of all offcut xrefs to the code unit
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
	 * Populates the provided lists with the direct and offcut xrefs to the specified variable
	 * 
	 * @param var     variable to get references
	 * @param xrefs   list to put direct references in
	 * @param offcuts list to put offcut references in
	 */
	public static void getVariableRefs(Variable var, List<Reference> xrefs,
			List<Reference> offcuts) {
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
	 * Returns the direct and offcut xrefs to the specified variable
	 * 
	 * @param var variable to get references
	 * @return the set of references
	 */
	public static Set<Reference> getVariableRefs(Variable var) {

		Set<Reference> results = new HashSet<>();
		Address addr = var.getMinAddress();
		if (addr == null) {
			return results;
		}

		Program program = var.getFunction().getProgram();
		ReferenceManager refMgr = program.getReferenceManager();
		Reference[] vrefs = refMgr.getReferencesTo(var);
		for (Reference vref : vrefs) {
			results.add(vref);
		}
		return results;
	}

	/**
	 * Shows all xrefs to the given location in a new table.  These xrefs are retrieved
	 * from the given supplier.  Thus, it is up to the client to determine which xrefs to show.
	 * 
	 * @param navigatable the navigatable used for navigation from the table
	 * @param serviceProvider the service provider needed to wire navigation
	 * @param service the service needed to show the table
	 * @param location the location for which to find references
	 * @param xrefs the xrefs to show
	 */
	public static void showAllXrefs(Navigatable navigatable, ServiceProvider serviceProvider,
			TableService service, ProgramLocation location, Set<Reference> xrefs) {

		ReferencesFromTableModel model =
			new ReferencesFromTableModel(new ArrayList<>(xrefs), serviceProvider,
				location.getProgram());
		TableComponentProvider<ReferenceEndpoint> provider = service.showTable(
			"XRefs to " + location.getAddress().toString(), "XRefs", model, "XRefs", navigatable);
		provider.installRemoveItemsAction();
	}

	/**
	 * Returns all xrefs to the given location.  If in data, then xrefs to the specific data
	 * component will be returned.  Otherwise, the code unit containing the address of the
	 * given location will be used as the source of the xrefs.
	 * 
	 * @param location the location for which to get xrefs
	 * @return the xrefs
	 */
	public static Set<Reference> getAllXrefs(ProgramLocation location) {

		CodeUnit cu = DataUtilities.getDataAtLocation(location);
		if (cu == null) {
			Address toAddress = location.getAddress();
			Listing listing = location.getProgram().getListing();
			cu = listing.getCodeUnitContaining(toAddress);
		}

		Reference[] xrefs = getXReferences(cu, ALL_REFS);
		Reference[] offcuts = getOffcutXReferences(cu, ALL_REFS);

		// Remove duplicates
		Set<Reference> set = new HashSet<>();
		CollectionUtils.addAll(set, xrefs);
		CollectionUtils.addAll(set, offcuts);
		return set;
	}
}
