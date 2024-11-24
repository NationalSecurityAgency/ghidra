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
package ghidra.app.util.pdb.classtype;

import java.util.*;

import ghidra.app.util.SymbolPath;
import ghidra.app.util.demangler.DemangledException;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.microsoft.MicrosoftDemangler;
import ghidra.app.util.demangler.microsoft.MicrosoftMangledContext;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.mem.Memory;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import mdemangler.MDParsableItem;
import mdemangler.naming.MDQualification;
import mdemangler.naming.MDQualifier;
import mdemangler.object.MDObjectCPP;
import mdemangler.typeinfo.*;

/**
 * This class manages MSFT-compliant virtual function tables and virtual base tables for our
 * program.
 * <p>
 * This class also provide lookup mechanisms for locating the appropriate tables desired for
 * for particular MSFT-compliant classes of the program.  This is particularly useful for
 * determining how classes are laid down in memory and for determining which virtual method
 * gets called for a class.
 * <p>
 * The initial design has been shelved for now due to issues.  For now, the design relies on
 * a stinky solution that assumes the order of the tables in memory is that same as the order of
 * the pointers to these tables in the owner class.  This seems true based on limited experience.
 * Hoping to revisit this soon.
 */
public class MsftVxtManager extends VxtManager {

	private Memory memory;
	private Map<String, Address> vxtAddressByMangled;
	private Map<String, ParentageNode> parentageNodeByMangled;

	// These two are for an interim solution where we believe that the order of these tables in
	//  memory are the same order that their pointers appear in the classes... this is based solely
	//  on limited experience.  The solution stinks and would benefit from the original direction
	//  of using the parentage.  We will try to use the parentage as a litmus test on retrieval
	private Map<ClassID, TreeMap<Address, VBTable>> vbtsByOwner;
	private Map<ClassID, TreeMap<Address, VFTable>> vftsByOwner;

	// Used for locating vft and vbt
	// These are explicitly used for storing/retrieving the "program" versions which result from
	//  locating and parsing the mangled strings for these tables.  It is possible that these
	//  could be used for placeholder or other versions... TBD
	private ParentageNode mixedRoot; // originally had separate roots for VFT and VBT

	/**
	 * Constructor for this class
	 * @param ctm the class type manager
	 * @param memory the memory of the program
	 */
	public MsftVxtManager(ClassTypeManager ctm, Memory memory) {
		super(ctm);
		this.memory = memory;
		vxtAddressByMangled = new HashMap<>();
		parentageNodeByMangled = new HashMap<>();
		vbtsByOwner = new HashMap<>();
		vftsByOwner = new HashMap<>();
		mixedRoot = new ParentageNode(null);
	}

	/**
	 * Finds the putative {@link VBTable} in memory requested for the owning class
	 * @param owner the owning class of the table
	 * @return the table
	 */
	public VBTable findPrimaryVbt(ClassID owner) {
		TreeMap<Address, VBTable> map = vbtsByOwner.get(owner);
		if (map == null) {
			return null;
		}
		return map.firstEntry().getValue();
	}

	/**
	 * Finds the putative {@link VFTable} in memory requested for the owning class
	 * @param owner the owning class of the table
	 * @return the table
	 */
	public VFTable findPrimaryVft(ClassID owner) {
		TreeMap<Address, VFTable> map = vftsByOwner.get(owner);
		if (map == null) {
			return null;
		}
		return map.firstEntry().getValue();
	}

	/**
	 * Finds the putative {@link VBTable} in memory requested for the owning class and the
	 * specified parentage
	 * @param owner the owning class of the table
	 * @param parentage the parentage for the desired table.  The parentage must start with the
	 * parent that contains the pointer to the table and should include the ordered lineage from
	 * that class through all of its decendents to the owner, excluding the owner
	 * @return the table
	 */
	public VBTable findVbt(ClassID owner, List<ClassID> parentage) {
		ParentageNode node = findNode(owner, parentage);
		if (node == null) {
			return null;
		}
		VBTable vbTable = node.getVBTable();
		if (vbTable != null || !parentage.isEmpty()) { // see note below
			return vbTable;
		}
		// Not 100% sure on this... needs more investigation as to why there are mangled strings
		//  that reference the owner in the parentage.  Could there be a situation where there
		//  is one with the parentage and one without?  We are treating them as the same for now
		//  unless we find counter-examples or difficulties with this.
		// Above, we test of parentage.isEmpty, because this special case comes into play only
		//  if it was empty
		node = findNode(owner, List.of(owner));
		if (node == null) {
			return null;
		}
		return node.getVBTable();
	}

	/**
	 * Finds the putative {@link VFTable} in memory requested for the owning class and the
	 * specified parentage
	 * @param owner the owning class of the table
	 * @param parentage the parentage for the desired table.  The parentage must start with the
	 * parent that contains the pointer to the table and should include the ordered lineage from
	 * that class through all of its decendents to the owner, excluding the owner
	 * @return the table
	 */
	public VFTable findVft(ClassID owner, List<ClassID> parentage) {
		ParentageNode node = findNode(owner, parentage);
		if (node == null) {
			return null;
		}
		VFTable vfTable = node.getVFTable();
		if (vfTable != null || !parentage.isEmpty()) { // see note below
			return vfTable;
		}
		// Not 100% sure on this... needs more investigation as to why there are mangled strings
		//  that reference the owner in the parentage.  Could there be a situation where there
		//  is one with the parentage and one without?  We are treating them as the same for now
		//  unless we find counter-examples or difficulties with this.
		// Above, we test of parentage.isEmpty, because this special case comes into play only
		//  if it was empty
		node = findNode(owner, List.of(owner));
		if (node == null) {
			return null;
		}
		return node.getVFTable();
	}

	/**
	 * Creates a virtual function and base tables for the {@code Map<String, Address>} of
	 * addresses-by-mangled names.  Any failures are logged
	 *
	 * @param categoryPath the base category path used for the collection of class-related
	 * types
	 * @param addressByMangledName the map of addresses-by-mangled-names
	 * @param log the message log
	 * @param monitor the task monitor
	 * @throws CancelledException upon user cancellation
	 */
	public void createVirtualTables(CategoryPath categoryPath,
			Map<String, Address> addressByMangledName, MessageLog log, TaskMonitor monitor)
			throws CancelledException {
		for (Map.Entry<String, Address> entry : addressByMangledName.entrySet()) {
			monitor.checkCancelled();
			String mangled = entry.getKey();
			Address address = entry.getValue();
			if (!createVirtualTable(categoryPath, mangled, address, monitor)) {
				log.appendMsg("Could not create VxTable for " + mangled);
			}
		}
	}

	/**
	 * Creates a virtual function or base table for the mangled symbol and its associated
	 * memory address
	 *
	 * @param categoryPath the base category path used for the collection of class-related
	 * types
	 * @param mangled the mangled name of the type
	 * @param address the address associated with the mangled name
	 * @param monitor the task monitor
	 * @return {@code true} if successful
	 */
	public boolean createVirtualTable(CategoryPath categoryPath, String mangled, Address address,
			TaskMonitor monitor) {

		Address a = vxtAddressByMangled.get(mangled);
		if (a != null) {
			if (!a.equals(address)) {
				Msg.warn(this, String.format("New address (%s) does not match existing %s for: %s",
					a, address, mangled));
			}
			else {
				Msg.warn(this,
					String.format("Entry already exists: address (%s), %s", address, mangled));
			}
			return false;
		}
		vxtAddressByMangled.put(mangled, address);

		DemanglerResults demanglerResults = getOwnerAndUsersDtp(categoryPath, mangled);
		if (demanglerResults == null) {
			Msg.warn(this, "Problem obtaining path information from mangled symbol: " + mangled);
			return false;
		}

		OwnerAndParentage ownerAndParentage = demanglerResults.ownerAndParentage();
		ClassID owner = ownerAndParentage.owner();
		List<ClassID> parentage = ownerAndParentage.parentage();
		ParentageNode node = parentageNodeByMangled.get(mangled);
		if (node == null) {
			node = getOrAddParentageNode(categoryPath, mixedRoot, demanglerResults);
			if (node == null) {
				return false;
			}
			parentageNodeByMangled.put(mangled, node);
		}

		switch (demanglerResults.vtType()) {
			case VBT:
				ProgramVirtualBaseTable prvbt = new ProgramVirtualBaseTable(owner, parentage,
					memory, address, ctm.getDefaultVbtTableElementSize(), ctm, mangled);
				if (node.getVBTable() != null) {
					Msg.warn(this, "VBT already exists at node for " + mangled);
					return false;
				}
				node.setVBTable(prvbt);
				vbtByAddress.put(address, prvbt);
				storeVbt(owner, address, prvbt); // temp solution?
				break;

			case VFT:
				ProgramVirtualFunctionTable vft = new ProgramVirtualFunctionTable(owner, parentage,
					memory, address, ctm.getDefaultVftTableElementSize(), mangled);
				if (node.getVFTable() != null) {
					Msg.warn(this, "VFT already exists at node for " + mangled);
					return false;
				}
				node.setVFTable(vft);
				vftByAddress.put(address, vft);
				storeVft(owner, address, vft); // temp solution?
				break;

			default:
				throw new AssertException("Unhandled VtType: " + demanglerResults.vtType());
		}
		return true;
	}

	private void storeVbt(ClassID owner, Address address, VBTable vbt) {
		TreeMap<Address, VBTable> map = vbtsByOwner.get(owner);
		if (map == null) {
			map = new TreeMap<>();
			vbtsByOwner.put(owner, map);
		}
		map.put(address, vbt);
	}

	private void storeVft(ClassID owner, Address address, VFTable vft) {
		TreeMap<Address, VFTable> map = vftsByOwner.get(owner);
		if (map == null) {
			map = new TreeMap<>();
			vftsByOwner.put(owner, map);
		}
		map.put(address, vft);
	}

	private ParentageNode findNode(ClassID owner, List<ClassID> parentage) {
		if (!(owner instanceof ProgramClassID ownerGId)) {
			return null;
		}
		SymbolPath ownerSp = ownerGId.getSymbolPath();
		ParentageNode ownerNode = mixedRoot.getBranch(ownerSp.toString());
		if (ownerNode == null) {
			return null;
		}
		ParentageNode resultNode = null;
		ParentageNode node = ownerNode;
		for (ClassID id : parentage) {
			if (!(id instanceof ProgramClassID gId)) {
				return null;
			}
			SymbolPath sp = gId.getSymbolPath();
			ParentageNode next = node.getBranch(sp.toString());
			if (next != null) {
				node = next;
				resultNode = node;
			}
			// Regardless of found or not, go to next in parentage.
			//  Skips unnecessary peer-through parents
		}
		if (resultNode == null) {
			return ownerNode;
		}
		// Need to have found at least one in parentage, but since the owner is part of our
		//  parentage tree, we cannot use the fact that we are still on owner (which can also
		//  be in our parentage list) as the flag for knowing if we found something in the
		//  parentage, so we have a separate found flag
		return resultNode;
	}

	private ParentageNode getOrAddParentageNode(CategoryPath categoryPath, ParentageNode root,
			DemanglerResults demanglerResults) {

		ParentageNode node = root;
		OwnerAndParentage ownerAndParentage = demanglerResults.ownerAndParentage();

		ClassID owner = ownerAndParentage.owner(); // owner should be same as first on list
		List<ClassID> parentage = ownerAndParentage.parentage();
		if (!(owner instanceof ProgramClassID)) {
			Msg.error(this, "ClassID error for " + ownerAndParentage);
			return null;
		}
		ProgramClassID gId = (ProgramClassID) owner;
		node = node.getOrAddBranch(gId.getSymbolPath().toString());
		for (ClassID id : parentage) {
			if (!(id instanceof ProgramClassID)) {
				Msg.error(this, "ClassID error for " + ownerAndParentage);
				return null;
			}
			gId = (ProgramClassID) id;
			node = node.getOrAddBranch(gId.getSymbolPath().toString());
		}
		return node;
	}

	private static MDParsableItem doDemangle(String mangledString) {
		MicrosoftDemangler demangler = new MicrosoftDemangler();
		// Options, Program, and Address will have no bearing on what we are looking for
		MicrosoftMangledContext context =
			demangler.createMangledContext(mangledString, null, null, null);
		try {
			DemangledObject demangledObject = demangler.demangle(context);
			if (demangledObject == null) {
				// Couldn't demangle.
				return null;
			}
			return demangler.getMdItem();
		}
		catch (DemangledException e) {
			// Couldn't demangle.
			return null;
		}
	}

	private enum VtType {
		VFT, VBT
	}

	private record OwnerAndParentage(ClassID owner, List<ClassID> parentage) {}

	private record DemanglerResults(VtType vtType, OwnerAndParentage ownerAndParentage) {}

	/**
	 * Gets the owner and users of the VxT from the mangled name
	 * @param categoryPath the base CategoryPath for types tree being used
	 * @param mangledString the mangled string to be decoded
	 * @return the associated complex type or null if the string couldn't be demangled
	 */
	private static DemanglerResults getOwnerAndUsersDtp(CategoryPath categoryPath,
			String mangledString) {
		MDParsableItem parsableItem = doDemangle(mangledString);

		if (!(parsableItem instanceof MDObjectCPP cppItem)) {
			return null;
		}
		MDTypeInfo typeInfo = cppItem.getTypeInfo();
		if (!(typeInfo instanceof MDVxTable vxTable)) {
			return null;
		}

		SymbolPath ownerSp = getOwnerSymbolPath(cppItem.getQualification());
		List<SymbolPath> parentageSps = getParentageSymbolPaths(vxTable.getNestedQualifications());

		List<ClassID> parentage = new ArrayList<>();
		ClassID owner = new ProgramClassID(categoryPath, ownerSp);
		for (SymbolPath sp : parentageSps) {
			ClassID user = new ProgramClassID(categoryPath, sp);
			parentage.add(user); // owner is the parentage if parentageSps was empty
		}

		OwnerAndParentage ownerAndParentage = new OwnerAndParentage(owner, parentage);

		return switch (typeInfo) {
			case MDVFTable f -> new DemanglerResults(VtType.VFT, ownerAndParentage);
			case MDVBTable b -> new DemanglerResults(VtType.VBT, ownerAndParentage);
			default -> null;
		};
	}

	private static List<SymbolPath> getParentageSymbolPaths(List<MDQualification> qualifications) {
		if (qualifications == null) {
			return null;
		}
		List<SymbolPath> paths = new ArrayList<>();
		for (MDQualification qualification : qualifications) {
			SymbolPath symbolPath = getOwnerSymbolPath(qualification);
			paths.add(symbolPath);
		}
		return paths;
	}

	private static SymbolPath getOwnerSymbolPath(MDQualification qualification) {
		Iterator<MDQualifier> it = qualification.iterator();
		if (!it.hasNext()) {
			return null;
		}
		List<String> parts = new ArrayList<>();
		do {
			MDQualifier qual = it.next();
			parts.add(0, qual.toString());
		}
		while (it.hasNext());
		return new SymbolPath(parts);
	}

	//==============================================================================================

	private static class ParentageNode {
		private ParentageNode parent = null;
		private Map<String, ParentageNode> branches;
		private String name;
		// Might want to store more than just one VXT... could store generic, pdb, program
		//  versions... could mix function and base too (one tree instead of two)?
		private VFTable vft;
		private VBTable vbt;

		private ParentageNode(String name) {
			this.name = name;
			branches = new HashMap<>();
		}

		private ParentageNode getOrAddBranch(String branchName) {
			ParentageNode branch = branches.get(branchName);
			if (branch == null) {
				branch = new ParentageNode(branchName);
				branch.parent = this;
				branches.put(branchName, branch);
			}
			return branch;
		}

		private ParentageNode getBranch(String branchName) {
			return branches.get(branchName);
		}

		private void setVFTable(VFTable vftArg) {
			vft = vftArg;
		}

		private void setVBTable(VBTable vbtArg) {
			vbt = vbtArg;
		}

		private VFTable getVFTable() {
			return vft;
		}

		private VBTable getVBTable() {
			return vbt;
		}

		@SuppressWarnings("unused")
		private String getName() {
			return name;
		}

		@SuppressWarnings("unused")
		private ParentageNode getParent() {
			return parent;
		}

	}

}
