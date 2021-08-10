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

import generic.stl.Pair;
import ghidra.program.model.data.*;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;

/// Creates an acyclic dependency list of data types.
public class DataTypeDependencyOrderer {

	public static class Entry {
		protected long id;
		protected DataType dataType;

		@Override
		public int hashCode() {
			int val = (int) id;
			val ^= (int) (id >>> 32);
			return val;
		}

		@Override
		public boolean equals(Object op2) {
			return id == ((Entry) op2).id;
		}
	}

	private Boolean processed = false;
	private DataTypeManager dtManager;

	// A HashSet is chosen so that we have no duplicates.
	private HashSet<Entry> inputSet = new HashSet<>();

	private HashSet<Entry> procSet = new HashSet<>();
	private HashSet<Entry> doneSet = new HashSet<>();
	private ArrayList<DataType> structList = new ArrayList<>();
	private ArrayList<DataType> orderedDependentsList = new ArrayList<>();

	private HashMap<Entry, Set<Entry>> whoIDependOn = new HashMap<>();
	private HashMap<Entry, Set<Entry>> whoDependsOnMe = new HashMap<>();
	private LinkedList<Entry> noDependentsQueue = new LinkedList<>();

	/**
	 * Associate a DataType with its ID (relative to the DataTypeManager) in an Entry
	 * @param dt is the raw DataType
	 * @return the Entry with both DataType and ID
	 */
	private Entry createEntry(DataType dt) {
		if (dt.getDataTypeManager() != dtManager) {
			dt = dt.clone(dtManager);
		}
		Entry result = new Entry();
		result.dataType = dt;
		result.id = dtManager.getID(dt);
		return result;
	}

	/**
	 * This method adds a single DataTypes to the input DataType list and
	 *  marks the data as dirty (all must need recalculated).
	 * @param dataType  A single DataType to add to the input DataType list.
	 */
	public void addType(DataType dataType) {
		if (dataType == null) {
			return;
		}
		inputSet.add(createEntry(dataType));
		processed = false;
	}

	/**
	 * This method adds a list of DataTypes to the input DataType list and
	 *  marks the data as dirty (all must need recalculated).
	 * @param dtlist  List of DataTypes to add to the input DataType list.
	 */
	public void addTypeList(ArrayList<DataType> dtlist) {
		for (DataType dt : dtlist) {
			if (dt == null) {
				continue;
			}
			inputSet.add(createEntry(dt));
		}
		processed = false;
	}

	/**
	 * This method removes a DataType from the list and
	 *  marks the data as dirty (all must need recalculated).
	 * @param dataType  The DataType to remove from the input list
	 */
	public void removeType(DataType dataType) {
		if (dataType == null) {
			return;
		}
		inputSet.remove(createEntry(dataType));
		processed = false;
	}

	/**
	 * This method clears the input DataType list and
	 *  marks the data as dirty (all must need recalculated).
	 */
	public void clear() {
		inputSet.clear();
		processed = false;
	}

	/**
	 * This constructor starts with an empty DataType list, which can be added to.
	 * @param dtManager the manager used to extract IDs
	 */
	public DataTypeDependencyOrderer(DataTypeManager dtManager) {
		this.dtManager = dtManager;
	}

	/**
	 * This constructor takes an initial DataType list.
	 * @param dtManager the manager used to extract IDs
	 * @param dtlist  Initial list of DataTypes to order
	 */
	public DataTypeDependencyOrderer(DataTypeManager dtManager, ArrayList<DataType> dtlist) {
		this.dtManager = dtManager;
		addTypeList(dtlist);
	}

	/**
	 * This method returns two lists:
	 * 1) is the set of structs. Intended for outputting zero-sized definitions.
	 * 2) is the acyclic dependency list (broken at structs and pointers to structs)
	 * This works (and the dependency graph is able to be broken of cycles) because
	 *  structures can be given zero size to start with and then later updated with full size.
	 * @return  pair of arrayLists--one of structs and one complete list of dependents
	 */
	public Pair<ArrayList<DataType>, ArrayList<DataType>> getAcyclicDependencyLists() {
		if (processed == false) {
			processDependencyLists();
		}
		return new Pair<>(structList, orderedDependentsList);
	}

	/**
	 * This method returns the ArrayList of structs
	 *  to structs found in the input list, intended
	 *  to be used initially as zero-sized structures.
	 * @return  An arrayList of structs
	 */
	public ArrayList<DataType> getStructList() {
		if (processed == false) {
			processDependencyLists();
		}
		return structList;
	}

	/**
	 * This returns the acyclic dependency list (broken at structs and pointers to structs)
	 * @return  An ArrayList of dependents.
	 */
	public ArrayList<DataType> getDependencyList() {
		if (processed == false) {
			processDependencyLists();
		}
		return orderedDependentsList;
	}

	/**
	 * @return  String of debug data.
	 */
	private String dumpDebug() {
		StringBuffer res = new StringBuffer();
		res.append("\nDepend Size\n  orderedDependentsList: " + orderedDependentsList.size() +
			"\n  whoIDependOn: " + whoIDependOn.size() + "\n  whoDependsOnMe: " +
			whoDependsOnMe.size() + "\n\n");
		if (!orderedDependentsList.isEmpty()) {
			for (DataType dt : orderedDependentsList) {
				res.append(
					"Ordered Dependents: " + dt.getName() + " " + dt.getClass().getName() + "\n");
			}
		}
		res.append("\n");
		if (!whoDependsOnMe.isEmpty()) {
			for (Entry entry : whoDependsOnMe.keySet()) {
				res.append("WhoDependsOnMe Me: " + entry.dataType.getName() + " " +
					entry.dataType.getClass().getName() + "\n");
				for (Entry dentry : whoDependsOnMe.get(entry)) {
					res.append("              Dep: <-- " + dentry.dataType.getName() + " " +
						dentry.dataType.getClass().getName() + "\n");
				}
			}
		}
		res.append("\n");
		if (!whoIDependOn.isEmpty()) {
			for (Entry entry : whoIDependOn.keySet()) {
				res.append("WhoIDependOn I: " + entry.dataType.getName() + " " +
					entry.dataType.getClass().getName() + "\n");
				for (Entry dentry : whoIDependOn.get(entry)) {
					res.append("            Sup: --> " + dentry.dataType.getName() + " " +
						dentry.dataType.getClass().getName() + "\n");
				}
			}
		}
		return res.toString();
	}

	private void processDependencyLists() {
		try {
			createAcyclicDependencyLists();
		}
		catch (Exception e) {
			//If exception, return a basic list of inputs.
			structList.clear();
			orderedDependentsList.clear();
			for (Entry entry : inputSet) {
				orderedDependentsList.add(entry.dataType);
			}
			Msg.error(this, e);
		}
		processed = true;
	}

	private void createAcyclicDependencyLists() {
		whoDependsOnMe.clear();
		whoIDependOn.clear();
		noDependentsQueue.clear();
		structList.clear();
		orderedDependentsList.clear();
		procSet.clear();
		procSet.addAll(inputSet);
		doneSet.clear();

		//Set up dependency graph edges
		while (!procSet.isEmpty()) {
			Entry entry = procSet.iterator().next();
			DataType dataType = entry.dataType;
			//Msg.debug(this, "SET_SIZE: " + procSet.size());
			//Msg.debug(this, "DTYPE_IN: " + dataType.getName());
			if (dataType instanceof Pointer) {
				addDependent(entry, ((Pointer) dataType).getDataType());
			}
			else if (dataType instanceof Array) {
				addDependent(entry, ((Array) dataType).getDataType());
			}
			else if (dataType instanceof TypeDef) {
				addDependent(entry, ((TypeDef) dataType).getDataType());
			}
			else if (dataType instanceof Structure) {
				Structure struct = (Structure) dataType;
				DataTypeComponent dtcomps[] = struct.getDefinedComponents();
				for (DataTypeComponent dtcomp : dtcomps) {
					addDependent(entry, dtcomp.getDataType());
				}
			}
			else if (dataType instanceof Composite) {
				DataTypeComponent dtcomps[] = ((Composite) dataType).getComponents();
				for (DataTypeComponent dtcomp : dtcomps) {
					addDependent(entry, dtcomp.getDataType());
				}
			}
			else if (dataType instanceof FunctionDefinition) {
				ParameterDefinition paramDefs[] = ((FunctionDefinition) dataType).getArguments();
				addDependent(entry, ((FunctionDefinition) dataType).getReturnType());
				for (ParameterDefinition paramDef : paramDefs) {
					addDependent(entry, paramDef.getDataType());
				}
			}
			else {  //Includes BuiltIn types, etc.
				addDependent(entry);
//				orderedDependentsList.add(dataType); //These weren't originally on the list, but should cause not harm.
//				Msg.debug(this,
//					"NO_LIST ITEM: " + dataType.getName() + "\n  Size: " + dataType.getLength());
			}
			doneSet.add(entry);
			procSet.remove(entry);
		}

//		Msg.debug(this, dumpDebug());

		//Create dependentsStack by traversing and trimming edges of now-acyclic dependency graph
		//
		//Locate starting types: those that are not dependent on other types.
		if (whoDependsOnMe.isEmpty()) {
			throw new AssertException("Cannot create dependency graph on data types.");
		}
		for (Entry entry : doneSet) {
			if (!whoIDependOn.containsKey(entry) || (whoIDependOn.get(entry).size() == 0)) {
				noDependentsQueue.add(entry);
				whoIDependOn.remove(entry);
			}
		}

		// Place noDependents types into the depentsStack and remove edges to types that are
		//  dependent on them, checking to see if these dependents are no longer dependent on any
		//  other types, and thus placing them in the noDependents stack for their processing. 
		while (!noDependentsQueue.isEmpty()) {
			Entry entry = noDependentsQueue.remove();
			//dependency stack of all types.
			//Msg.debug(this, "ORDERED_LIST_SIZE: " + orderedDependentsList.size() + " -- TYPE: " +
			//	dataType.getName());
			orderedDependentsList.add(entry.dataType);
			//dependency stack of struct for which zero-sized structs should first be used.
			if (entry.dataType instanceof Structure) {
				structList.add(entry.dataType);
			}
			removeMyDependentsEdgesToMe(entry);
		}
		if (!whoDependsOnMe.isEmpty() || !whoIDependOn.isEmpty()) {
			throw new AssertException(
				"Cycles still exist in the data type dependency graph. Debug follows.\n" +
					dumpDebug());
		}
	}

	private void addDependent(Entry entry, DataType subType) {
		//subtype might be null, but don't expect entry to be null, but error?
		if ((entry == null) || (subType == null)) {
			return;
		}
		if (subType instanceof BitFieldDataType) {
			subType = ((BitFieldDataType) subType).getBaseDataType();
		}
		Entry subEntry = createEntry(subType);
		if (!doneSet.contains(subEntry)) {
			procSet.add(subEntry);
		}
		if (entry.dataType instanceof Pointer) { //avoid cycles with structures/composites
			if (subType instanceof Structure) {
				return;
			}
		}
		Set<Entry> dependents = whoDependsOnMe.get(subEntry);
		if (dependents == null) {
			dependents = new HashSet<>();
			whoDependsOnMe.put(subEntry, dependents);
		}
		dependents.add(entry); //ignores duplicates
		Set<Entry> support = whoIDependOn.get(entry);
		if (support == null) {
			support = new HashSet<>();
			whoIDependOn.put(entry, support);
		}
		support.add(subEntry); //ignores duplicates
	}

	private void addDependent(Entry entry) {
		if (entry == null) {
			return;
		}
		Set<Entry> dependents = whoDependsOnMe.get(entry);
		if (dependents == null) {
			dependents = new HashSet<>();
			whoDependsOnMe.put(entry, dependents);
		}
		Set<Entry> support = new HashSet<>();
		whoIDependOn.put(entry, support);
	}

	private void removeMyDependentsEdgesToMe(Entry entry) {
		Set<Entry> myDependents = whoDependsOnMe.get(entry);
		if (myDependents != null) {
			Iterator<Entry> myDependentsIter = myDependents.iterator();
			while (myDependentsIter.hasNext()) {
				Entry myDependent = myDependentsIter.next();
				//get reverse information to delete forward information.
				Set<Entry> supportSet = whoIDependOn.get(myDependent);
				supportSet.remove(entry);
				if (supportSet.size() == 0) {
					noDependentsQueue.add(myDependent);
					whoIDependOn.remove(myDependent);
				}
			}
			myDependents.clear();
			whoDependsOnMe.remove(entry);
		}
	}
}
