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
package ghidra.program.model.lang.protorules;

import static ghidra.program.model.pcode.ElementId.*;

import java.io.IOException;
import java.util.ArrayList;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.Encoder;
import ghidra.util.exception.InvalidInputException;
import ghidra.xml.*;

/**
 *  A rule controlling how parameters are assigned addresses
 *  
 *  Rules are applied to a parameter in the context of a full function prototype.
 *  A rule applies only for a specific class of data-type associated with the parameter, as
 *  determined by its DatatypeFilter, and may have other criteria limiting when it applies
 *  (via QualifierFilter).
 */
public class ModelRule {
	private DatatypeFilter filter;			// Which data-types this rule applies to
	private QualifierFilter qualifier;		// Additional qualifiers for when the rule should apply (if non-null)
	private AssignAction assign;			// How the Address should be assigned
	private AssignAction[] sideeffects;		// Extra actions that happen on success

	public ModelRule() {
		filter = null;
		qualifier = null;
		assign = null;
	}

	/**
	 * Copy constructor
	 * @param op2 is the ModelRule to copy from
	 * @param res is the new resource set to associate with the copy
	 * @throws InvalidInputException if necessary resources are not present in the resource set
	 */
	public ModelRule(ModelRule op2, ParamListStandard res) throws InvalidInputException {
		if (op2.filter != null) {
			filter = op2.filter.clone();
		}
		else {
			filter = null;
		}
		if (op2.qualifier != null) {
			qualifier = op2.qualifier.clone();
		}
		else {
			qualifier = null;
		}
		if (op2.assign != null) {
			assign = op2.assign.clone(res);
		}
		else {
			assign = null;
		}
		sideeffects = new AssignAction[op2.sideeffects.length];
		for (int i = 0; i < op2.sideeffects.length; ++i) {
			sideeffects[i] = op2.sideeffects[i].clone(res);
		}
	}

	/**
	 * Construct from components
	 * 
	 * The provided components are cloned into the new object.
	 * @param typeFilter is the data-type filter the rule applies before performing the action
	 * @param action is the action that will be applied
	 * @param res is the resource list to which this rule will be applied
	 * @throws InvalidInputException if necessary resources are missing from the list
	 */
	public ModelRule(DatatypeFilter typeFilter, AssignAction action, ParamListStandard res)
			throws InvalidInputException

	{
		filter = typeFilter.clone();
		qualifier = null;
		assign = action.clone(res);
		sideeffects = new AssignAction[0];
	}

	public boolean isEquivalent(ModelRule op) {
		if (assign == null && op.assign == null) {
			// Nothing to compare
		}
		else if (assign != null && op.assign != null) {
			if (!assign.isEquivalent(op.assign)) {
				return false;
			}
		}
		else {
			return false;
		}
		if (filter == null && op.filter == null) {
			// Nothing to compare
		}
		else if (filter != null && op.filter != null) {
			if (!filter.isEquivalent(op.filter)) {
				return false;
			}
		}
		else {
			return false;
		}
		if (qualifier == null && op.qualifier == null) {
			// Nothing to compare
		}
		else if (qualifier != null && op.qualifier != null) {
			if (!qualifier.isEquivalent(op.qualifier)) {
				return false;
			}
		}
		else {
			return false;
		}
		if (sideeffects.length != op.sideeffects.length) {
			return false;
		}
		for (int i = 0; i < sideeffects.length; ++i) {
			if (!sideeffects[i].isEquivalent(op.sideeffects[i])) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Assign an address and other details for a specific parameter or for return storage in context
	 * 
	 * The Address is only assigned if the data-type filter and the optional qualifier filter
	 * pass, otherwise a FAIL response is returned.
	 * If the filters pass, the Address is assigned based on the AssignAction specific to
	 * this rule, and the action's response code is returned.
	 * @param dt is the data-type of the parameter or return value
	 * @param proto is the high-level description of the function prototype
	 * @param pos is the position of the parameter (pos>=0) or return storage (pos=-1)
	 * @param dtManager is a data-type manager for (possibly) transforming the data-type
	 * @param status is the resource consumption array
	 * @param res will hold the resulting description of the parameter
	 * @return the response code
	 */
	public int assignAddress(DataType dt, PrototypePieces proto, int pos, DataTypeManager dtManager,
			int[] status, ParameterPieces res) {
		if (!filter.filter(dt)) {
			return AssignAction.FAIL;
		}
		if (qualifier != null && !qualifier.filter(proto, pos)) {
			return AssignAction.FAIL;
		}
		int response = assign.assignAddress(dt, proto, pos, dtManager, status, res);
		if (response != AssignAction.FAIL) {
			for (int i = 0; i < sideeffects.length; ++i) {
				sideeffects[i].assignAddress(dt, proto, pos, dtManager, status, res);
			}
		}
		return response;
	}

	/**
	 * Encode this rule to a stream
	 * @param encoder is the stream encode
	 * @throws IOException for problems with the stream
	 */
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_RULE);
		filter.encode(encoder);
		if (qualifier != null) {
			qualifier.encode(encoder);
		}
		assign.encode(encoder);
		for (int i = 0; i < sideeffects.length; ++i) {
			sideeffects[i].encode(encoder);
		}
		encoder.closeElement(ELEM_RULE);
	}

	/**
	 * Decode this rule from stream
	 * 
	 * @param parser is the stream decoder
	 * @param res is the parameter resource list owning this rule
	 * @throws XmlParseException if there are problems decoding are missing resources
	 */
	public void restoreXml(XmlPullParser parser, ParamListStandard res) throws XmlParseException

	{
		XmlElement elemId = parser.start(ELEM_RULE.name());
		filter = DatatypeFilter.restoreFilterXml(parser);
		ArrayList<QualifierFilter> qualifierList = new ArrayList<>();
		for (;;) {
			QualifierFilter tmpFilter = QualifierFilter.restoreFilterXml(parser);
			if (tmpFilter == null) {
				break;
			}
			qualifierList.add(tmpFilter);
		}
		if (qualifierList.size() == 0) {
			qualifier = null;
		}
		else if (qualifierList.size() == 1) {
			qualifier = qualifierList.get(0);
			qualifierList.clear();
		}
		else {
			qualifier = new AndFilter(qualifierList);
		}
		assign = AssignAction.restoreActionXml(parser, res);
		ArrayList<AssignAction> sideList = new ArrayList<>();
		for (;;) {
			XmlElement subEl = parser.peek();
			if (!subEl.isStart()) {
				break;
			}
			sideList.add(AssignAction.restoreSideeffectXml(parser, res));
		}
		sideeffects = new AssignAction[sideList.size()];
		sideList.toArray(sideeffects);
		parser.end(elemId);
	}

}
