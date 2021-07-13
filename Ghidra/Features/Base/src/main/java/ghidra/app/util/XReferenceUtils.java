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

public class XReferenceUtils {

	// Methods in this class treat -1 as a key to return all references and
	// not cap the result set.
	private final static int ALL_REFS = -1;

	/**
	 * Returns an array containing the first <b><code>max</code></b>
	 * direct xref references to the specified code unit.
	 * 
	 * @param cu the code unit to generate the xrefs
	 * @param max max number of xrefs to get, or -1 to get all references
	 * 
	 * @return array first <b><code>max</code></b> xrefs to the code unit
	 */
	public final static List<Reference> getXReferences(CodeUnit cu, int max) {
		Program program = cu.getProgram();
		if (program == null) {
			Collections.emptyList();
		}

		// lookup the direct xrefs to the current code unit
		List<Reference> xrefs = new ArrayList<>();
		Address minAddress = cu.getMinAddress();
		ReferenceIterator it = program.getReferenceManager().getReferencesTo(minAddress);
		while (it.hasNext()) {
			if (xrefs.size() - max == 0) {
				break;
			}

			Reference ref = it.next();
			xrefs.add(ref);
		}

		// Check for thunk reference
		Function func = program.getFunctionManager().getFunctionAt(minAddress);
		if (func != null) {
			Address[] thunkAddrs = func.getFunctionThunkAddresses();
			if (thunkAddrs != null) {
				for (Address thunkAddr : thunkAddrs) {
					xrefs.add(new ThunkReference(thunkAddr, func.getEntryPoint()));
				}
			}
		}
		return xrefs;
	}

	/**
	 * Returns an array containing all offcut xref references to the specified code unit
	 * 
	 * @param cu the code unit to generate the offcut xrefs
	 * @param max max number of offcut xrefs to get, or -1 to get all offcut references
	 * @return array of all offcut xrefs to the code unit
	 */
	public static List<Reference> getOffcutXReferences(CodeUnit cu, int max) {
		Program program = cu.getProgram();
		if (program == null) {
			return Collections.emptyList();
		}

		if (cu.getLength() <= 1) {
			return Collections.emptyList();
		}

		List<Reference> offcuts = new ArrayList<>();
		ReferenceManager refMgr = program.getReferenceManager();
		AddressSet set = new AddressSet(cu.getMinAddress().add(1), cu.getMaxAddress());
		AddressIterator it = refMgr.getReferenceDestinationIterator(set, true);
		while (it.hasNext()) {
			Address addr = it.next();
			ReferenceIterator refIter = refMgr.getReferencesTo(addr);
			while (refIter.hasNext()) {
				if (offcuts.size() - max == 0) {
					break;
				}

				Reference ref = refIter.next();
				offcuts.add(ref);
			}
		}

		return offcuts;
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
		getVariableRefs(var, xrefs, offcuts, ALL_REFS);
	}

	/**
	 * Populates the provided lists with the direct and offcut xrefs to the specified variable
	 * 
	 * @param var     variable to get references
	 * @param xrefs   list to put direct references in
	 * @param offcuts list to put offcut references in
	 * @param max max number of xrefs to get, or -1 to get all references
	 */
	public static void getVariableRefs(Variable var, List<Reference> xrefs,
			List<Reference> offcuts, int max) {

		Address addr = var.getMinAddress();
		if (addr == null) {
			return;
		}

		Program program = var.getFunction().getProgram();
		ReferenceManager refMgr = program.getReferenceManager();
		Reference[] refs = refMgr.getReferencesTo(var);
		int total = 0;
		for (Reference vref : refs) {
			if (total++ - max == 0) {
				break;
			}

			if (addr.equals(vref.getToAddress())) {
				xrefs.add(vref);
			}
			else {
				offcuts.add(vref);
			}
		}
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

		if (cu == null) {
			return Collections.emptySet();
		}

		List<Reference> xrefs = getXReferences(cu, ALL_REFS);
		List<Reference> offcuts = getOffcutXReferences(cu, ALL_REFS);

		// Remove duplicates
		Set<Reference> set = new HashSet<>();
		set.addAll(xrefs);
		set.addAll(offcuts);
		return set;
	}

	/**
	 * Shows all xrefs to the given location in a new table.
	 * 
	 * @param navigatable the navigatable used for navigation from the table
	 * @param serviceProvider the service provider needed to wire navigation
	 * @param service the service needed to show the table
	 * @param location the location for which to find references
	 * @param xrefs the xrefs to show
	 */
	public static void showXrefs(Navigatable navigatable, ServiceProvider serviceProvider,
			TableService service, ProgramLocation location, Collection<Reference> xrefs) {

		ReferencesFromTableModel model =
			new ReferencesFromTableModel(new ArrayList<>(xrefs), serviceProvider,
				location.getProgram());
		TableComponentProvider<ReferenceEndpoint> provider = service.showTable(
			"XRefs to " + location.getAddress().toString(), "XRefs", model, "XRefs", navigatable);
		provider.installRemoveItemsAction();
	}
}
