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
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.gclass.ClassID;
import ghidra.program.model.gclass.ClassUtils;
import ghidra.program.model.listing.Program;
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
 * <p><p>
 * This class also provide lookup mechanisms for locating the appropriate tables desired for
 * for particular MSFT-compliant classes of the program.  This is particularly useful for
 * determining how classes are laid down in memory and for determining which virtual method
 * gets called for a class.
 * <p><p>
 * The {@link #createVirtualTables(CategoryPath, Map, MessageLog, TaskMonitor)} and
 * {@link #createVirtualTable(CategoryPath, String, Address, TaskMonitor)} methods demangle
 * the strings and created tables within a owner/parentage tree based on the demangled information.
 * <p><p>
 * The {@link #findVbt(ClassID, List)} and {@link #findVft(ClassID, List)} methods attempt
 * to find the VF/VB tables by finding the appropriate node in the tree based upon owner and
 * at-times-mismatched parentage information from the user.  This mismatch is not necessarily
 * the fault of the user, but more due to what parentage is incorporated into the mangled name.
 * <p><p>
 * <B> DESIGN of find mechanism</B>
 * <p>
 * One might think that the parentage information used in the mangling scheme is inconsistent, but
 * we believe that is due to our not having a complete understanding of how the MSFT scheme adds
 * information to uniquely identify the tables.  Both VB and VF tables use the same parentage
 * scheme for mangling.  The scheme is one of a namespaced owner (the child class that will have
 * pointers to the tables) and a parentage that describes which table for the owner.  Once this
 * scheme is better understood, the information here should get updated.
 * <p><p>
 * Without getting into too much detail about the class hierarchy and layouts here, some examples
 * follow:
 * <pre>
 * struct ANS::A : virtual A1NS::A1, virtual A2NS:A2
 * struct BNS::B : virtual B1NS::B1, virtual B2NS:B2
 * struct DNS::D : CNS::C, ANS::A, BNS::B
 * struct ENS::E : ANS::A, BNS::B
 * struct INS::I : ...
 * struct JNS::J : ...
 * struct KNS::K : JNS::J
 * struct LNS::L : KNS::K
 * struct MNS::M : ENS::E, DNS::D, INS::I, LNS::L
 *
 * For struct M -> struct E -> struct A (nested vbtptr)
 * We have a mangled VB table coded as owner M and parentage {for A's E}
 * For struct M -> struct D -> struct C (nested vbtptr)
 * We have a mangled VB table coded as owner M and parentage {for C}
 * For struct M -> struct L -> struct K -> struct J (nested vbtptr)
 * We have a mangled VB table coded as owner M and no parentage
 * For struct M -> struct E -> struct B (nested vbtptr)
 * We have a mangled VB table coded as owner M and parentage {for B's E}, but for this case,
 *  B is a virtual class in E
 * For struct A -> A1, A2
 * We have a mangled VF table coded as owner A and parentage {for A}, which is itself.
 * </pre>
 * <p>
 * We view the first example as the most normal example where the base of M contains the base of E
 * which contains the base of A which contains a vbtptr.  So, as a user trying to find the table
 * associated with the vbtptr, we could use the nested of the base classes to come up with the
 * parentage, or we could, from the compile side, look at the class hierarchy.  Either way, if the
 * user trying to find the table passes in a parentage of {A, E}, we expect to return the obvious.
 * <p><p>
 * The second example is similar to the first.  Here, the base of M contains the base of D which
 * contains the base of D which contains a vbtptr.  If the user tries to pass in the parentage
 * of {D, C}, we still want to return the appropriate table, but we know the mangled scheme only
 * showed {C}.
 * <p><p>
 * For the third example, based on the nesting of classes, the user will pass in a parentage of
 * {J, K, L}, but we need the finder to return the table that has no parentage.
 * <p><p>
 * For the fourth example, the nesting no longer helps since base B is virtual within class M, but
 * based on hierarchy (compile-side), we know the M -> E -> B dependency, so if we pass in a
 * parentage of {B, E}, we expect to get the appropriate result.
 * <p><p>
 * For the last example, which is for owner A, the mangled string has also has a parentage of {A},
 * but a user trying to find the table wouldn't be expected to pass in a parentage of {A}, as A
 * is the owner.  We expect the finder to still appropriately return the correct table.
 */
public class MsftVxtManager extends VxtManager {

	private Program program;
	private Map<String, Address> vxtAddressByMangled;
	private Map<String, ParentageNode> parentageNodeByMangled;

	// These two are for an interim solution where we believe that the order of these tables in
	//  memory are the same order that their pointers appear in the classes... this is based solely
	//  on limited experience.  The solution stinks and would benefit from the original direction
	//  of using the parentage.  We will try to use the parentage as a litmus test on retrieval
	private Map<ClassID, List<VirtualBaseTable>> vbtsByOwner;
	private Map<ClassID, List<VirtualFunctionTable>> vftsByOwner;

	// Used for locating vft and vbt
	// These are explicitly used for storing/retrieving the "program" versions which result from
	//  locating and parsing the mangled strings for these tables.  It is possible that these
	//  could be used for placeholder or other versions... TBD
	private ParentageNode vbtRoot;
	private ParentageNode vftRoot;

	private Map<OwnerParentage, VirtualBaseTable> vbtsByOwnerParentage;
	private Map<OwnerParentage, VirtualFunctionTable> vftsByOwnerParentage;

	/**
	 * Constructor for this class
	 * @param ctm the class type manager
	 * @param program the program
	 */
	public MsftVxtManager(ClassTypeManager ctm, Program program) {
		super(ctm);
		this.program = program;
		vxtAddressByMangled = new HashMap<>();
		parentageNodeByMangled = new HashMap<>();
		vbtsByOwner = new HashMap<>();
		vftsByOwner = new HashMap<>();
		vbtRoot = new ParentageNode(null);
		vftRoot = new ParentageNode(null);
		vbtsByOwnerParentage = new HashMap<>();
		vftsByOwnerParentage = new HashMap<>();
	}

	/**
	 * Create the vxtable structures
	 * @param dtm the data type manager
	 */
	public void doTableLayouts(DataTypeManager dtm) {
		for (VirtualBaseTable vbt : vbtsByOwnerParentage.values()) {
			ClassID id = vbt.getOwner();
			vbt.getLayout(dtm, ClassUtils.getClassInternalsPath(id));
		}
		for (VirtualFunctionTable vft : vftsByOwnerParentage.values()) {
			ClassID id = vft.getOwner();
			vft.getLayout(dtm, ClassUtils.getClassInternalsPath(id));
		}
	}

	/**
	 * Finds the putative {@link VirtualBaseTable} in memory requested for the owning class
	 * @param owner the owning class of the table
	 * @param parentage the primary parentage (only used if creating placeholder)
	 * @return the table
	 */
	public VirtualBaseTable findPrimaryVbt(ClassID owner, List<ClassID> parentage) {
		List<VirtualBaseTable> list = vbtsByOwner.get(owner);
		if (list == null) {
			return null;
		}
		VirtualBaseTable result = null;
		VirtualBaseTable firstPlaceholder = null;
		Address addrResult = null;
		for (VirtualBaseTable table : list) {
			if (table instanceof ProgramVirtualBaseTable pvbt) {
				Address addr = pvbt.getAddress();
				if (addrResult == null || addr.compareTo(addrResult) < 0) {
					addrResult = addr;
					result = table;
				}
			}
			else if (firstPlaceholder == null) {
				firstPlaceholder = table;
			}
		}
		if (result == null) {
			if (firstPlaceholder != null) {
				return firstPlaceholder;
			}
			result = new PlaceholderVirtualBaseTable(owner, parentage);
			list.add(result);
		}
		return result;
	}

	/**
	 * Finds the putative {@link VirtualFunctionTable} in memory requested for the owning class
	 * @param owner the owning class of the table
	 * @param parentage the primary parentage (only used if creating placeholder)
	 * @return the table
	 */
	public VirtualFunctionTable findPrimaryVft(ClassID owner, List<ClassID> parentage) {
		List<VirtualFunctionTable> list = vftsByOwner.get(owner);
		if (list == null) {
			return null;
		}
		VirtualFunctionTable result = null;
		VirtualFunctionTable firstPlaceholder = null;
		Address addrResult = null;
		for (VirtualFunctionTable table : list) {
			if (table instanceof ProgramVirtualFunctionTable pvft) {
				Address addr = pvft.getAddress();
				if (addrResult == null || addr.compareTo(addrResult) < 0) {
					addrResult = addr;
					result = table;
				}
			}
			else if (firstPlaceholder == null) {
				firstPlaceholder = table;
			}
		}
		if (result == null) {
			if (firstPlaceholder != null) {
				return firstPlaceholder;
			}
			result = new PlaceholderVirtualFunctionTable(owner, parentage);
			list.add(result);
		}
		return result;
	}

	/**
	 * Returns the class IDs of all owners of VBTs
	 * @return the IDs
	 */
	public ClassID[] getAllVbtOwners() {
		ClassID ids[] = new ClassID[vbtsByOwner.size()];
		Set<ClassID> set = vbtsByOwner.keySet();
		return set.toArray(ids);
	}

	/**
	 * Returns the class IDs of all owners of VFTs
	 * @return the IDs
	 */
	public ClassID[] getAllVftOwners() {
		ClassID ids[] = new ClassID[vftsByOwner.size()];
		Set<ClassID> set = vftsByOwner.keySet();
		return set.toArray(ids);
	}

	/**
	 * Returns the ordered in-memory {@link VirtualBaseTable}s for the owning class
	 * @param owner the owning class of the table
	 * @return the tables
	 */
	public VirtualBaseTable[] getVbts(ClassID owner) {
		List<VirtualBaseTable> list = vbtsByOwner.get(owner);
		if (list == null) {
			return null;
		}
		return list.toArray(new VirtualBaseTable[list.size()]);
	}

	/**
	 * Returns the ordered in-memory {@link VirtualFunctionTable}s for the owning class
	 * @param owner the owning class of the table
	 * @return the tables
	 */
	public VirtualFunctionTable[] getVfts(ClassID owner) {
		List<VirtualFunctionTable> list = vftsByOwner.get(owner);
		if (list == null) {
			return null;
		}
		return list.toArray(new VirtualFunctionTable[list.size()]);
	}

	/**
	 * Finds the putative {@link VirtualBaseTable} in memory requested for the owning class and the
	 * specified parentage
	 * @param owner the owning class of the table
	 * @param parentage the parentage for the desired table.  The parentage must start with the
	 * parent that contains the pointer to the table and should include the ordered lineage from
	 * that class through all of its decendents to the owner, excluding the owner
	 * @return the table
	 */
	public VirtualBaseTable findVbt(ClassID owner, List<ClassID> parentage) {
		OwnerParentage op = new OwnerParentage(owner, parentage);
		VirtualBaseTable vbt = vbtsByOwnerParentage.get(op);
		if (vbt != null) {
			return vbt;
		}
		vbt = searchVbtTree(owner, parentage);
		if (vbt == null) {
			vbt = new PlaceholderVirtualBaseTable(owner, parentage);
		}
		vbtsByOwnerParentage.put(op, vbt);
		storeVbt(owner, vbt);
		return vbt;
	}

	private VirtualBaseTable searchVbtTree(ClassID owner, List<ClassID> parentage) {
		ParentageNode node = findNode(owner, parentage, vbtRoot);
		if (node == null) {
			return null;
		}
		VirtualBaseTable vbTable = node.getVBTable();
		if (vbTable != null || !parentage.isEmpty()) { // see note below
			return vbTable;
		}
		// Not 100% sure on this... needs more investigation as to why there are mangled strings
		//  that reference the owner in the parentage.  Could there be a situation where there
		//  is one with the parentage and one without?  We are treating them as the same for now
		//  unless we find counter-examples or difficulties with this.
		// Above, we test of parentage.isEmpty, because this special case comes into play only
		//  if it was empty
		node = findNode(owner, List.of(owner), vbtRoot);
		if (node == null) {
			return null;
		}
		return node.getVBTable();
	}

	/**
	 * Finds the putative {@link VirtualFunctionTable} in memory requested for the owning class
	 * and the specified parentage
	 * @param owner the owning class of the table
	 * @param parentage the parentage for the desired table.  The parentage must start with the
	 * parent that contains the pointer to the table and should include the ordered lineage from
	 * that class through all of its decendents to the owner, excluding the owner
	 * @return the table
	 */
	public VirtualFunctionTable findVft(ClassID owner, List<ClassID> parentage) {
		OwnerParentage op = new OwnerParentage(owner, parentage);
		VirtualFunctionTable vft = vftsByOwnerParentage.get(op);
		if (vft != null) {
			return vft;
		}
		vft = searchVftTree(owner, parentage);
		if (vft == null) {
			vft = new PlaceholderVirtualFunctionTable(owner, parentage);
		}
		vftsByOwnerParentage.put(op, vft);
		storeVft(owner, vft);
		return vft;
	}

	private VirtualFunctionTable searchVftTree(ClassID owner, List<ClassID> parentage) {

		ParentageNode node = findNode(owner, parentage, vftRoot);
		if (node == null) {
			return null;
		}
		VirtualFunctionTable vfTable = node.getVFTable();
		if (vfTable != null || !parentage.isEmpty()) { // see note below
			return vfTable;
		}
		// Not 100% sure on this... needs more investigation as to why there are mangled strings
		//  that reference the owner in the parentage.  Could there be a situation where there
		//  is one with the parentage and one without?  We are treating them as the same for now
		//  unless we find counter-examples or difficulties with this.
		// Above, we test of parentage.isEmpty, because this special case comes into play only
		//  if it was empty
		node = findNode(owner, List.of(owner), vftRoot);
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
			ParentageNode root = demanglerResults.vtType().equals(VtType.VBT) ? vbtRoot : vftRoot;
			node = getOrAddParentageNode(categoryPath, root, demanglerResults);
			if (node == null) {
				return false;
			}
			parentageNodeByMangled.put(mangled, node);
		}

		switch (demanglerResults.vtType()) {
			case VBT:
				ProgramVirtualBaseTable prvbt = new ProgramVirtualBaseTable(owner, parentage,
					program, address, ClassUtils.getVbtEntrySize(ctm.getDataTypeManager()),
					mangled);
				if (node.getVBTable() != null) {
					Msg.warn(this, "VBT already exists at node for " + mangled);
					return false;
				}
				node.setVBTable(prvbt);
				vbtByAddress.put(address, prvbt);
				storeVbt(owner, prvbt); // temp solution?
				break;

			case VFT:
				ProgramVirtualFunctionTable vft = new ProgramVirtualFunctionTable(owner, parentage,
					program, address, ctm.getDefaultVftTableElementSize(), mangled);
				if (node.getVFTable() != null) {
					Msg.warn(this, "VFT already exists at node for " + mangled);
					return false;
				}
				node.setVFTable(vft);
				vftByAddress.put(address, vft);
				storeVft(owner, vft); // temp solution?
				break;

			default:
				throw new AssertException("Unhandled VtType: " + demanglerResults.vtType());
		}
		return true;
	}

	private void storeVbt(ClassID owner, VirtualBaseTable vbt) {
		ClassID own = vbt.getOwner();
		List<VirtualBaseTable> list = vbtsByOwner.get(own);
		if (list == null) {
			list = new ArrayList<>();
			vbtsByOwner.put(owner, list);
		}
		List<ClassID> parentage = vbt.getParentage();
		for (VirtualBaseTable table : list) {
			if (isEqual(table.getParentage(), parentage)) {
				return; // return without saving
			}
		}
		list.add(vbt);
	}

	private void storeVft(ClassID owner, VirtualFunctionTable vft) {
		List<VirtualFunctionTable> list = vftsByOwner.get(owner);
		if (list == null) {
			list = new ArrayList<>();
			vftsByOwner.put(owner, list);
		}
		List<ClassID> parentage = vft.getParentage();
		for (VirtualFunctionTable table : list) {
			if (isEqual(table.getParentage(), parentage)) {
				return; // return without saving
			}
		}
		list.add(vft);
	}

	private boolean isEqual(List<ClassID> parentage1, List<ClassID> parentage2) {
		int diff = parentage1.size() - parentage2.size();
		if (diff != 0) {
			return false;
		}
		Iterator<ClassID> iter2 = parentage2.iterator();
		for (ClassID element : parentage1) {
			if (!element.equals(iter2.next())) {
				return false;
			}
		}
		return true;
	}

	private ParentageNode findNode(ClassID owner, List<ClassID> parentage, ParentageNode root) {
		SymbolPath ownerSp = owner.getSymbolPath();
		ParentageNode ownerNode = root.getBranch(ownerSp.toString());
		if (ownerNode == null) {
			return null;
		}
		ParentageNode resultNode = null;
		ParentageNode node = ownerNode;
		for (ClassID id : parentage) {
			SymbolPath sp = id.getSymbolPath();
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
		node = node.getOrAddBranch(owner.getSymbolPath().toString());
		for (ClassID id : parentage) {
			node = node.getOrAddBranch(id.getSymbolPath().toString());
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
		ClassID owner = new ClassID(categoryPath, ownerSp);
		for (SymbolPath sp : parentageSps) {
			ClassID user = new ClassID(categoryPath, sp);
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
		private VirtualFunctionTable vft;
		private VirtualBaseTable vbt;

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

		private void setVFTable(VirtualFunctionTable vftArg) {
			vft = vftArg;
		}

		private void setVBTable(VirtualBaseTable vbtArg) {
			vbt = vbtArg;
		}

		private VirtualFunctionTable getVFTable() {
			return vft;
		}

		private VirtualBaseTable getVBTable() {
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
