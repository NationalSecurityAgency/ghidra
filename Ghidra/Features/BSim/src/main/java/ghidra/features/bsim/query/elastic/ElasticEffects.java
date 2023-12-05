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
package ghidra.features.bsim.query.elastic;

import java.util.*;
import java.util.Map.Entry;

import ghidra.features.bsim.gui.filters.BSimFilterType;
import ghidra.features.bsim.query.protocol.*;

/**
 * Container for collecting an elasticsearch query filter document from BSimFilter elements
 *
 */
public class ElasticEffects {
	private int argumentCount = 0;
	private int filterMask = 0;				// Each 1-bit represents a single function tag that needs to be matched
	private int filterValue = 0;			// With the filterMask, bits indicate whether an individual
	//   function tag should match as true (1) or false(0)

	// Stand-alone filter element based on indexed executable fields
	private Map<BSimFilterType, List<String>> standaloneFilter = new TreeMap<BSimFilterType, List<String>>();

	// Set of executable docvalues we need for the script portion of the filter
	private Set<String> docValues = new TreeSet<String>();

	// Set of parameters used by the script portion of filter
	private Map<String,String> params = new TreeMap<String,String>();

	private Map<String,Long> dateParams = new TreeMap<String,Long>();

	// Collection of elasticsearch script string pieces, sorted by the FilterTemplate that created them
	private Map<BSimFilterType, List<String>> booleanElements =
		new TreeMap<BSimFilterType, List<String>>();

	// Ids of child functions, matching function must call
	private Set<String> childIds = new TreeSet<String>();

	private Map<String,String> funcParams = new TreeMap<String,String>();

	public String assignArgument() {
		argumentCount += 1;
		return "arg" + argumentCount;
	}

	public void addFunctionFilter(int flag, boolean val) {
		filterMask |= flag;				// Check the specific bit
		if (val) {
			filterValue |= flag;		//      must be set to 1		
		}
	}

	public void addStandalone(BSimFilterType filter,String value) {
		List<String> list = standaloneFilter.get(filter);
		if (list == null) {
			list = new ArrayList<String>();
			standaloneFilter.put(filter, list);
		}
		list.add(value);		
	}

	public void addScriptElement(BSimFilterType filter,String value) {
		List<String> list = booleanElements.get(filter);
		if (list == null) {
			list = new ArrayList<String>();
			booleanElements.put(filter, list);
		}
		list.add(value);
	}

	public void addDocValue(String val) {
		docValues.add(val);
	}

	public void addParam(String key,String val) {
		params.put(key, val);
	}

	public void addDateParam(String key,Date date) {
		dateParams.put(key, date.getTime());
	}

	public void addFuncParam(String key,String val) {
		funcParams.put(key, val);
	}

	public void addChildId(String id) {
		childIds.add(id);
	}

	private void buildStandaloneFilters(StringBuilder buffer) {
		boolean needComma = false;
		for(Entry<BSimFilterType, List<String>> entry : standaloneFilter.entrySet()) {
			List<String> termList = entry.getValue();

			for(String term : termList) {
				if (needComma) {
					buffer.append(',');
				}
				else {
					needComma = true;
				}
				buffer.append(term);
			}
		}
	}

	private void buildParentScript(StringBuilder buffer) {
		buffer.append("\"inline\": \"");
		for(String val : docValues) {
			buffer.append(val);
		}
		buffer.append("return ");
		boolean needsAnd = false;
		for(Entry<BSimFilterType, List<String>> entry : booleanElements.entrySet()) {
			BSimFilterType filter = entry.getKey();
			String val = filter.buildElasticCombinedClause(entry.getValue());
			if (needsAnd) {
				buffer.append(" && ");
			}
			else {
				needsAnd = true;
			}
			buffer.append(val);
		}
		buffer.append("\"");
		if ((!params.isEmpty()) || (!dateParams.isEmpty())) {
			buffer.append(", \"params\": {");
			boolean needsComma = false;
			for(Entry<String,String> entry : params.entrySet()) {
				if (needsComma) {
					buffer.append(", ");
				}
				else {
					needsComma = true;
				}
				buffer.append('\"').append(entry.getKey()).append("\": \"");
				buffer.append(entry.getValue()).append('\"');
			}
			for(Entry<String,Long> entry : dateParams.entrySet()) {
				if (needsComma) {
					buffer.append(", ");
				}
				else {
					needsComma = true;
				}
				buffer.append('\"').append(entry.getKey()).append("\": ");
				buffer.append(entry.getValue());		// Emit value as a JSON long integer
			}
			buffer.append("} ");
		}
	}

	private void buildParentFilterDocument(StringBuilder buffer) {
		buffer.append("\"filter\": { ");
		buffer.append("\"has_parent\": { ");
		buffer.append("\"parent_type\": \"exe\", ");
		buffer.append("\"query\": { ");
		buffer.append("\"bool\": { ");
		boolean needsComma = false;
		if (!standaloneFilter.isEmpty()) {
			buildStandaloneFilters(buffer);
			needsComma = true;
		}
		if (!booleanElements.isEmpty()) {
			if (needsComma) {
				buffer.append(',');
			}
			buffer.append("\"filter\": { ");
			buffer.append("\"script\": { \"script\": { ");
			buildParentScript(buffer);
			buffer.append("} } }");
		}
		buffer.append("} } } }");
	}

	private void buildFunctionScriptFilter(StringBuilder buffer) {
		boolean needsAnd = false;
		buffer.append("\"filter\": {");
		buffer.append("\"script\": { \"script\": { ");
		buffer.append("\"inline\": \"");
		if (filterMask != 0) {
			buffer.append("int flags = (int)doc['flags'].value; ");
		}
		if (!childIds.isEmpty()) {
			buffer.append("def childid = doc['childid']; ");
		}
		buffer.append("return ");
		if (filterMask !=0) {
			buffer.append("((flags & params.mask) == params.value)");
			needsAnd = true;
		}
		for(String id : childIds) {
			if (needsAnd) {
				buffer.append(" && ");
			}
			buffer.append(id);
			needsAnd = true;
		}
		buffer.append("\", \"params\": { ");
		boolean needsComma = false;
		if (filterMask != 0) {
			buffer.append("\"mask\": ").append(filterMask);
			buffer.append(", \"value\": ").append(filterValue);
			needsComma = true;
		}
		for(Entry<String,String> entry : funcParams.entrySet()) {
			if (needsComma) {
				buffer.append(", ");
			}
			else {
				needsComma = true;
			}
			buffer.append('\"').append(entry.getKey()).append("\": \"");
			buffer.append(entry.getValue()).append('\"');			
		}
		buffer.append("} } } }");
	}

	public String buildFunctionFilter() {
		StringBuilder buffer = new StringBuilder();
		if ((filterMask != 0) || (!childIds.isEmpty())) {
			buffer.append(", ");
			buildFunctionScriptFilter(buffer);
		}
		if ((!booleanElements.isEmpty()) || (!standaloneFilter.isEmpty())) {
			buffer.append(", ");
			buildParentFilterDocument(buffer);
		}
		return buffer.toString();
	}

	public static String createFilter(BSimFilter filter,IDElasticResolution[] idres) throws ElasticException {
		ElasticEffects effects = new ElasticEffects();

		for (int i = 0; i < filter.numAtoms(); ++i) {
			FilterAtom atom = filter.getAtom(i);
			atom.type.gatherElasticEffect(effects, atom, idres[i]);
		}
		return effects.buildFunctionFilter();
	}
}
