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

// Search for the root cause of a datatype conflict based upon a selected datatype.
//@category Data Types
import java.util.*;

import javax.help.UnsupportedOperationException;

import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;

public class FindDataTypeConflictCauseScript extends GhidraScript {

	private DataTypeManager dtm;
	private HashSet<Integer> previouslyDetectedPairHashes;
	private boolean hasReport;

	@Override
	protected void run() throws Exception {

		previouslyDetectedPairHashes = new HashSet<>();

		PluginTool tool = state.getTool();
		if (tool == null) {
			throw new UnsupportedOperationException("headless use not supported");
		}

		DataTypeManagerService dtmService = tool.getService(DataTypeManagerService.class);
		if (dtmService == null) {
			popup("Tool does not contain a DataTypeManagerService!");
			return;
		}

		List<DataType> selectedDatatypes = dtmService.getSelectedDatatypes();
		if (selectedDatatypes.size() != 1) {
			popup("Select a single conflict datatype before running script");
			return;
		}

		DataType selectedDt = DataTypeUtilities.getBaseDataType(selectedDatatypes.get(0));
		if (selectedDt == null) {
			popup("Selected datatype must not be a default Pointer");
			return;
		}

		dtm = selectedDt.getDataTypeManager();
		Category cat = dtm.getCategory(selectedDt.getCategoryPath());

		int count = 0;
		for (DataType dt : cat.getDataTypesByBaseName(selectedDt.getName())) {
			if (dt == selectedDt || dt instanceof Pointer || dt instanceof Array) {
				continue;
			}
			++count;
			findRootDifferences(null, selectedDt, null, dt);
		}

		if (!hasReport) {
			println(
				"No apparent differences found when checking " + count + " type conflicts for '" +
					DataTypeUtilities.getNameWithoutConflict(selectedDt, false) + "'");
			if (count != 0) {
				println(
					"NOTE: This may be the result of a known resolve bug where a conflict decision\n" +
						"was made prior to resolving a referenced datatype (see GP-3632).");
			}
		}
	}

	private void findRootDifferences(DataType p1, DataType dt1, DataType p2, DataType dt2) {

		if (dt1 == dt2) {
			return;
		}

		if (!previouslyDetectedPairHashes.add(getPairHash(dt1, dt2))) {
			return; // skip if previously checked
		}

		// System.out.println("Compare " + dt1.getName() + " with " + dt2.getName());

		if (!DataTypeUtilities.getNameWithoutConflict(dt1, true)
				.equals(DataTypeUtilities.getNameWithoutConflict(dt2, true))) {
			report("Referenced type pathnames differ", p1, dt1, p2, dt2);
			return;
		}

		if (dt1.getClass() != dt2.getClass()) {
			report("Types are fundamentally different", p1, dt1, p2, dt2);
			return;
		}

		if (dt1 instanceof Structure s1) {
			findRootCompositeDifferences(p1, s1, p2, (Structure) dt2);
		}
		else if (dt1 instanceof Union u1) {
			findRootCompositeDifferences(p1, u1, p2, (Union) dt2);
		}
		else if (dt1 instanceof FunctionDefinition f1) {
			findRootFunctionDifferences(p1, f1, p2, (FunctionDefinition) dt2);
		}
		else if (dt1 instanceof TypeDef t1) {
			TypeDef t2 = (TypeDef) dt2;
			findRootDifferences(t1, t1.getDataType(), t2, t2.getDataType());
		}
		else if (dt1 instanceof Enum e1) {
			if (!e1.isEquivalent(dt2)) {
				report("Enums are different", p1, dt1, p2, dt2);
			}
		}
		else if (dt1 instanceof Pointer ptr1 && dt2 instanceof Pointer ptr2) {
			if (ptr1.hasLanguageDependantLength() != ptr2.hasLanguageDependantLength()) {
				String detail = "(" +
					(ptr1.hasLanguageDependantLength() ? "dynamic"
							: Integer.toString(8 * ptr1.getLength())) +
					"/" + (ptr2.hasLanguageDependantLength() ? "dynamic"
							: Integer.toString(8 * ptr2.getLength())) +
					")";
				report("Pointers are not both dynamic-length " + detail, p1, dt1, p2, dt2);
			}
			else if (ptr1.getLength() != ptr2.getLength()) {
				String detail = "(" + Integer.toString(8 * ptr1.getLength()) + "/" +
					Integer.toString(8 * ptr2.getLength()) + ")";
				report("Fixed-length pointers vary in length " + detail, p1, dt1, p2, dt2);
			}
			else {
				findRootDifferences(p1, ptr1.getDataType(), p2, ptr2.getDataType());
			}
		}
		else if (dt1 instanceof Array a1 && dt2 instanceof Array a2) {
			if (a1.getNumElements() != a2.getNumElements()) {
				report("Array dimensions differ", p1, dt1, p2, dt2);
			}
			else {
				findRootDifferences(p1, a1.getDataType(), p2, a2.getDataType());
			}
		}
		else if (!dt1.isEquivalent(dt2)) {
			report("Types are not equivalent", p1, dt1, p2, dt2);
		}
	}

	private void findRootFunctionDifferences(DataType p1, FunctionDefinition f1, DataType p2,
			FunctionDefinition f2) {

		boolean bailout = false;
		StringBuilder buf = null;
		if (!Objects.equals(f1.getCallingConventionName(), f2.getCallingConventionName())) {
			buf = appendMsg(buf, "Calling conventions (" + f1.getCallingConventionName() + "/" +
				f2.getCallingConventionName() + ")");
		}
		if (f1.hasNoReturn() != f2.hasNoReturn()) {
			buf =
				appendMsg(buf, "Has noreturn (" + f1.hasNoReturn() + "/" + f2.hasNoReturn() + ")");
		}
		if (f1.hasVarArgs() != f2.hasVarArgs()) {
			buf = appendMsg(buf, "Has varargs (" + f1.hasVarArgs() + "/" + f2.hasVarArgs() + ")");
			bailout = true;
		}

		ParameterDefinition[] args1 = f1.getArguments();
		ParameterDefinition[] args2 = f2.getArguments();
		if (args1.length != args2.length) {
			buf = appendMsg(buf, "Number of args differs");
			bailout = true;
		}
		else {
			for (int ix = 0; ix < args1.length; ix++) {
				if (!args1[ix].getName().equals(args2[ix].getName())) {
					buf = appendMsg(buf, "Argument names differs");
					break;
				}
			}
		}

		if (buf != null) {
			report("Function attributes differ: " + buf, p1, f1, p2, f2);
			if (bailout) {
				return;
			}
		}

		findRootDifferences(f1, f1.getReturnType(), f2, f2.getReturnType());

		for (int ix = 0; ix < args1.length; ix++) {
			findRootDifferences(f1, args1[ix].getDataType(), f2, args2[ix].getDataType());
		}

	}

	private void findRootCompositeDifferences(DataType p1, Composite s1, DataType p2,
			Composite s2) {

		boolean bailout = false;
		StringBuilder buf = null;

		DataTypeComponent[] dtc1 = s1.getDefinedComponents();
		DataTypeComponent[] dtc2 = s2.getDefinedComponents();

		if (s1.getLength() != s2.getLength()) {
			buf = appendMsg(buf, "Length differs (" + s1.getLength() + "/" + s2.getLength() + ")");
			bailout = true;
		}

		if (dtc1.length != dtc2.length) {
			buf = appendMsg(buf,
				"Number of defined components differ (" + dtc1.length + "/" + dtc2.length + ")");
			bailout = true;
		}

		if (s1.getAlignmentType() != s2.getAlignmentType()) {
			buf = appendMsg(buf, "Alignment type differs (" + s1.getAlignmentType() + "/" +
				s2.getAlignmentType() + ")");
		}

		if (s1.getPackingType() != s2.getPackingType()) {
			buf = appendMsg(buf,
				"Packing type differs (" + s1.getPackingType() + "/" + s2.getPackingType() + ")");
		}

		if (s1.getExplicitPackingValue() != s2.getExplicitPackingValue()) {
			buf = appendMsg(buf, "Explicit pack value differs (" + s1.getExplicitPackingValue() +
				"/" + s2.getExplicitPackingValue() + ")");
		}

		if (s1.getExplicitMinimumAlignment() != s2.getExplicitMinimumAlignment()) {
			buf = appendMsg(buf, "Explicit min-alignment differs (" +
				s1.getExplicitMinimumAlignment() + "/" + s2.getExplicitMinimumAlignment() + ")");
		}

		if (!s1.isPackingEnabled() && !s2.isPackingEnabled() && dtc1.length == dtc2.length) {
			for (int ix = 0; ix < dtc1.length; ix++) {
				if (dtc1[ix].getOffset() != dtc2[ix].getOffset() ||
					dtc1[ix].getLength() != dtc2[ix].getLength()) {
					buf = appendMsg(buf, "Component offsets/lengths vary)");
					bailout = true;
					break;
				}
			}
		}

		if (buf != null) {
			report("Composite attributes differ: " + buf, p1, s1, p2, s2);
			if (bailout) {
				return;
			}
		}

		for (int ix = 0; ix < dtc1.length; ix++) {
			findRootDifferences(s1, dtc1[ix].getDataType(), s2, dtc2[ix].getDataType());
		}

	}

	private StringBuilder appendMsg(StringBuilder buf, String msg) {
		if (buf == null) {
			buf = new StringBuilder();
		}
		if (buf.length() != 0) {
			buf.append(", ");
		}
		buf.append(msg);
		return buf;
	}

	private void report(String msg, DataType p1, DataType dt1, DataType p2, DataType dt2) {
		hasReport = true;
		println(msg + ":");
		println(" " + dt1.getPathName() + " (" + dt1.getClass().getSimpleName() + ")");
		if (p1 != null) {
			println("    used by >> " + p1.getPathName());
		}
		println(" " + dt2.getPathName() + " (" + dt2.getClass().getSimpleName() + ")");
		if (p2 != null) {
			println("    used by >> " + p2.getPathName());
		}
	}

	private int getPairHash(DataType dt1, DataType dt2) {
		Long id1 = dtm.getID(dt1);
		Long id2 = dtm.getID(dt2);
		if (id1 < id2) {
			// order IDs before hashing
			Long tmp = id1;
			id1 = id2;
			id2 = tmp;
		}
		return Objects.hash(id1, id2);
	}

}
