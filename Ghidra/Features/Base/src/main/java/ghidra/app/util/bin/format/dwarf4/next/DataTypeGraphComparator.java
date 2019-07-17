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
package ghidra.app.util.bin.format.dwarf4.next;

import java.util.*;

import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.util.Msg;

/**
 * Compares two {@link DataType} directed graphs, calling a
 * {@link DataTypePairObserver#observe(DataType, DataType) method} that can observe each
 * DataType pair that occupy equivalent positions in each graph.
 * <p>
 * The first/left DataType graph is assumed to be composed of {@link DataTypeImpl} instances,
 * and the second/right DataType graph is assumed to be composed of DataType DB instances.
 * <p>
 * Only DataTypes in the left graph are followed and may lead to a possible match with
 * the right graph.
 * <p>
 * This class is used to help transfer mappings that point to impl DataTypes to also point them
 * at the resultant 'db' DataTypes that are created by the DataTypeManager.
 */
public class DataTypeGraphComparator {
	public interface DataTypePairObserver {

		/**
		 * Callback method called with a {@link DataType} from the first/left/src graph and
		 * its matching DataType element from the second/right/dest graph.
		 * <p>
		 * This callback can choose to abort traversing the tree of child types if it returns
		 * false.  (ie. if this was a Pointer DataType, returning false would stop
		 * the graph comparator from comparing the DataType pointed to by this Pointer)
		 * <p>
		 *
		 * @param dt1 element from the first/left/src DataType graph
		 * @param dt2 matching element from the second/right/dest DataType graph
		 * @return false if abort this subtree, true if continue
		 */
		public boolean observe(DataType dt1, DataType dt2);
	}

	/**
	 * Compares two {@link DataType datatypes} graphs, calling the observer callback
	 * for each paired DataType that occupy equivalent positions in each graph.
	 * <p>
	 * @param preDT - Original (impl) DataType from before submitting to DataTypeManager.
	 * @param postDT - Result DataType from the DataTypeManager
	 * @param observer - Callback called for each position in the preDT graph that has a matching
	 * position in the postDT graph.
	 */
	public static void compare(DataType preDT, DataType postDT, DataTypePairObserver observer) {
		DataTypeGraphComparator dtgc = new DataTypeGraphComparator(observer);
		dtgc.compare(preDT, postDT);
	}

	private DataTypePairObserver observer;

	/**
	 * Object instance identity map used to prevent recursive loops when following
	 * DataType pointers and such.  DataType path/name mapping can't be used because
	 * there is no guarantee that impl DataType's have unique names.
	 * <p>
	 * Using a Map as a Set because there is no IdentityHashSet. (the value of the map entry
	 * is not used, just the key set)
	 */
	private IdentityHashMap<DataType, DataType> visitedTypes = new IdentityHashMap<>();

	private DataTypeGraphComparator(DataTypePairObserver observer) {
		this.observer = observer;
	}

	private void compare(DataType preDT, DataType postDT) {
		if (visitedTypes.containsKey(preDT)) {
			return;
		}
		visitedTypes.put(preDT, preDT);
		if (!observer.observe(preDT, postDT)) {
			return;
		}

		if (preDT instanceof Pointer && postDT instanceof Pointer) {
			compare((Pointer) preDT, (Pointer) postDT);
		}
		else if (preDT instanceof Array && postDT instanceof Array) {
			compare((Array) preDT, (Array) postDT);
		}
		else if (preDT instanceof Enum && postDT instanceof Enum) {
			compare((Enum) preDT, (Enum) postDT);
		}
		else if (preDT instanceof TypeDef && postDT instanceof TypeDef) {
			compare((TypeDef) preDT, (TypeDef) postDT);
		}
		else if (preDT instanceof FunctionDefinition && postDT instanceof FunctionDefinition) {
			compare((FunctionDefinition) preDT, (FunctionDefinition) postDT);
		}
		else if (preDT instanceof Structure && postDT instanceof Structure) {
			compare((Structure) preDT, (Structure) postDT);
		}
		else if (preDT instanceof Union && postDT instanceof Union) {
			compare((Union) preDT, (Union) postDT);
		}
	}

	private void compare(Pointer pre, Pointer post) {
		if (pre.getLength() != post.getLength()) {
			Msg.error(this, "Ptr types don't match: " + pre + ", " + post);
			return;
		}
		compare(pre.getDataType(), post.getDataType());
	}

	private void compare(Enum pre, Enum post) {
		if (pre.getLength() != post.getLength()) {
			Msg.error(this, "Enum data type sizes don't match: " + pre + ", " + post);
			return;
		}
	}

	private void compare(Array pre, Array post) {
		compare(pre.getDataType(), post.getDataType());
	}

	private void compare(TypeDef pre, TypeDef post) {
		compare(pre.getDataType(), post.getDataType());
	}

	private void compare(FunctionDefinition pre, FunctionDefinition post) {
		compare(pre.getReturnType(), post.getReturnType());

		ParameterDefinition[] preArgs = pre.getArguments();
		ParameterDefinition[] postArgs = post.getArguments();
		if (preArgs.length != postArgs.length) {
			return;
		}

		for (int i = 0; i < preArgs.length; i++) {
			ParameterDefinition prePD = preArgs[i];
			ParameterDefinition postPD = postArgs[i];

			compare(prePD.getDataType(), postPD.getDataType());
		}
	}

	private void compare(Structure pre, Structure post) {
		for (DataTypeComponent dtc : pre.getComponents()) {
			DataType preDTCType = dtc.getDataType();
			DataTypeComponent postDTC = post.getComponentAt(dtc.getOffset());
			if (postDTC == null) {
				continue;
			}

			String dtcFN = dtc.getFieldName();
			String postFN = postDTC.getFieldName();
			if (postFN != null && postFN.equals(dtcFN)) {
				compare(preDTCType, postDTC.getDataType());
			}
		}
	}

	private void compare(Union pre, Union post) {
		Map<String, DataTypeComponent> postCompsByName = new HashMap<>();
		for (DataTypeComponent dtc : post.getComponents()) {
			if (dtc.getFieldName() != null) {
				postCompsByName.put(dtc.getFieldName(), dtc);
			}
		}
		for (DataTypeComponent preDTC : pre.getComponents()) {
			DataTypeComponent postDTC = postCompsByName.get(preDTC.getFieldName());
			if (postDTC != null) {
				compare(preDTC.getDataType(), postDTC.getDataType());
			}
		}
	}

}
