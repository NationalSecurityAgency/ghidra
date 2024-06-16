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
package ghidra.features.bsim.query.protocol;

import java.io.IOException;
import java.io.Writer;
import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import ghidra.features.bsim.gui.filters.BSimFilterType;
import ghidra.features.bsim.gui.filters.FunctionTagBSimFilterType;
import ghidra.features.bsim.query.description.ExecutableRecord;
import ghidra.features.bsim.query.description.FunctionDescription;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * Suitable for client side filtering by calling isFiltered with an ExecutableRecord
 * or evaluate with a FunctionDescription. Contains information for passing filter to 
 * server side. Each 'atom' of the filter (FilterAtom) is expressed as an operator and 
 * a value string. The operator (FilterType) indicates what part of the ExecutableRecord 
 * or FunctionDescription must match (or not match) the value string.
 */
public class BSimFilter {
	private List<FilterAtom> atoms;
	private int filterflags_mask; // (mask,value) pair for what bits should be
	// set/unset in FunctionDescription flags
	private int filterflags_value;

	// Cached maps used by the evaluate method
	private Map<String, List<FilterAtom>> filterNameToFilterMapAND;
	private Map<String, List<FilterAtom>> filterNameToFilterMapOR;

	public BSimFilter() {
		atoms = new ArrayList<FilterAtom>();
		filterflags_mask = 0;
		filterflags_value = 0;
		filterNameToFilterMapAND = null;
		filterNameToFilterMapOR = null;
	}

	public int numAtoms() {
		return atoms.size();
	}

	public FilterAtom getAtom(int i) {
		return atoms.get(i);
	}

	public void addAtom(BSimFilterType type, String val) {
		if (type.isChildFilter()) {
			String exe = "unknown";
			if (val.charAt(0) == '[') {
				int i = val.indexOf(']');
				if (i >= 0) {
					exe = val.substring(1, i);
					val = val.substring(i + 1);
				}
			}
			ChildAtom childatom = new ChildAtom();
			childatom.type = type;
			childatom.value = null;
			childatom.name = val;
			childatom.exename = exe;
			atoms.add(childatom);
		}
		else {
			FilterAtom newatom = new FilterAtom(type, val);
			if (newatom.isValid()) {
				atoms.add(newatom);
				if (type instanceof FunctionTagBSimFilterType) {			// If this is a function tag filter
					int flag = ((FunctionTagBSimFilterType) type).getFlag();
					filterflags_mask |= flag;						// Accumulate the mask/value pair here
					if (newatom.value.equals("true")) {
						filterflags_value |= flag;
					}
				}
			}
		}
	}

	@Override
	public BSimFilter clone() {
		BSimFilter op2 = new BSimFilter();
		for (int i = 0; i < atoms.size(); ++i) {
			op2.atoms.add(atoms.get(i).clone());
		}
		op2.filterflags_mask = filterflags_mask;
		op2.filterflags_value = filterflags_value;
		return op2;
	}

	public void clear() {
		atoms.clear();
		filterflags_mask = 0;
		filterflags_value = 0;
	}

	public boolean isEmpty() {
		if (filterflags_mask != 0) {
			return false;
		}
		for (int i = 0; i < atoms.size(); ++i) {
			if (!atoms.get(i).type.isBlank()) {
				return false;
			}
		}
		return true;
	}

	public void saveXml(Writer fwrite) throws IOException {
		fwrite.append("<exefilter>");
		if (filterflags_mask != 0) {
			fwrite.append("<flags mask=\"");
			fwrite.append(SpecXmlUtils.encodeUnsignedInteger(filterflags_mask));
			fwrite.append("\">");
			fwrite.append(SpecXmlUtils.encodeUnsignedInteger(filterflags_value));
			fwrite.append("</flags>\n");
		}
		for (int i = 0; i < atoms.size(); ++i) {
			atoms.get(i).saveXml(fwrite);
		}
		fwrite.append("</exefilter>\n");
	}

	public void restoreXml(XmlPullParser parser) {
		parser.start("exefilter");
		atoms.clear();
		while (parser.peek().isStart()) {
			XmlElement el = parser.peek();
			if (el.getName().equals("flags")) {
				el = parser.start();
				filterflags_mask = SpecXmlUtils.decodeInt(el.getAttribute("mask"));
				filterflags_value = SpecXmlUtils.decodeInt(parser.end().getText());
			}
			else if (el.getName().equals("childatom")) {
				ChildAtom newatom = new ChildAtom();
				newatom.restoreXml(parser);
				atoms.add(newatom);
			}
			else {
				FilterAtom newatom = new FilterAtom();
				newatom.restoreXml(parser);
				atoms.add(newatom);
			}
		}
		parser.end();
	}

	/**
	 * Returns true if all filters resolve correctly for the given function description. There are 
	 * 4 main types of filters, each of which must be evaluated differently:
	 * 
	 * 1) Positive Filter: 	"<filter name> matches <filter value>". 
	 *    	For these, filter out any result that does not contain all elements (at a minimum) of the 
	 *    	filter value.
	 *    	ie: FILTER = "SetA", 		RESULT = "SetA" => keep it
	 * 		    FILTER = "SetA, SetB", 	RESULT = "SetA"	=> filter out
	 * 
	 * 2) Negative Filter: 	"<filter name> does not match <filter value>"
	 * 		For these, filter out any result that does not contain EXACTLY the filter value.
	 * 		ie: FILTER = "SetA", 		RESULT = "SetA, SetB"   => keep it
	 * 		    FILTER = "SetA, SetB", 	RESULT = "SetA, SetB"	=> filter out
	 * 
	 * 3) Positive Exe Filter: 	Same as #1, but custom exe filters are stored differently than
	 * 		'normal' categories and must be processed separately.
	 * 
	 * 4) Negative Exe Filter:	Same as #2, but custom exe filters are stored differently than
	 * 		'normal' categories and must be processed separately.
	 * 
	 * @param func the function description
	 * @return true if all filters resolve to true
	 */
	public boolean evaluate(FunctionDescription func) {

		if ((func.getFlags() & filterflags_mask) != filterflags_value) {
			return false;
		}

		ExecutableRecord exe = func.getExecutableRecord();

		if (filterNameToFilterMapAND == null) {
			populateFilterMaps();
		}

		return processFilters(exe);
	}

	/**
	 * Sets up the filterNameToFilter... maps with the appropriate category/filter values. This is done to
	 * keep all the filters of the same type in the same place.
	 * 
	 * ie: 	If one of the filters set is the "Executable name does not equal" filter, and gives it
	 * 		two values: "dexdump" and "stty", then the "filterNameToFilterMapOR" map will 
	 * 		have the following:
	 * 			key: 	"Executable name does not equal"
	 * 			value: 	[dexdump, stty]
	 * 
	 */
	private void populateFilterMaps() {
		// First set up maps to organize which filters should be AND'd together and 
		// which ones should be OR'd.
		filterNameToFilterMapAND = new HashMap<>();
		filterNameToFilterMapOR = new HashMap<>();

		for (FilterAtom atom : atoms) {

			// The name of the filter will be the map key (ie: "executable name equals"),
			// so grab it here.
			String name = atom.type.getLabel();

			BSimFilterType filter = atom.type;

			if (filter.orMultipleEntries()) {
				if (!filterNameToFilterMapOR.containsKey(name)) {
					List<FilterAtom> list = new ArrayList<FilterAtom>();
					list.add(atom);
					filterNameToFilterMapOR.put(name, list);
				}
				else {
					filterNameToFilterMapOR.get(name).add(atom);
				}
			}
			else {
				if (!filterNameToFilterMapAND.containsKey(name)) {
					List<FilterAtom> list = new ArrayList<FilterAtom>();
					list.add(atom);
					filterNameToFilterMapAND.put(name, list);
				}
				else {
					filterNameToFilterMapAND.get(name).add(atom);
				}
			}
		}
	}

	/**
	 * Takes all the entries in the 4 filter maps and uses them to determine which rows
	 * should be kept and which should be filtered out.
	 * 
	 * @param exe the executable record
	 * @return true if the record should be kept, false if not
	 */
	private boolean processFilters(ExecutableRecord exe) {

		// Check the standard positive filters ("does match")
		for (Map.Entry<String, List<FilterAtom>> entry : filterNameToFilterMapAND.entrySet()) {
			List<FilterAtom> value = entry.getValue();
			if (!evaluateAND(value, exe)) {
				return false;
			}
		}

		// Check the standard negative filters ("does not match")
		for (Map.Entry<String, List<FilterAtom>> entry : filterNameToFilterMapOR.entrySet()) {
			List<FilterAtom> value = entry.getValue();
			if (!evaluateOR(value, exe)) {
				return false;
			}
		}

		// If we're here, then it passed all tests, so return true.
		return true;
	}

	/**
	 * Return true only if ALL filters evaluate to true.
	 * 
	 * @param filters the list of all filters
	 * @param exe the executable record
	 * @return true if all filters evaluate to true
	 */
	private boolean evaluateAND(List<FilterAtom> filters, ExecutableRecord exe) {

		for (FilterAtom filter : filters) {
			if (!filter.evaluate(exe)) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Return true if any ONE of the atoms evaluates to true.
	 * 
	 * @param filters the list of all filters
	 * @param exe the executable record
	 * @return true if all filters evaluate to true
	 */
	private boolean evaluateOR(List<FilterAtom> filters, ExecutableRecord exe) {

		for (FilterAtom filter : filters) {
			if (filter.evaluate(exe)) {
				return true;
			}
		}

		return false;
	}

	public void replaceWith(BSimFilter other) {
		this.atoms = other.atoms;
		this.filterflags_mask = other.filterflags_mask;
		this.filterflags_value = other.filterflags_value;
	}

	public List<FilterEntry> getFilterEntries() {
		List<FilterEntry> filterStrings = new ArrayList<>();
		if (filterNameToFilterMapAND == null) {
			populateFilterMaps();
		}
		for (Entry<String, List<FilterAtom>> entry : filterNameToFilterMapOR.entrySet()) {
			List<FilterAtom> atomList = entry.getValue();
			filterStrings.add(new FilterEntry(atomList.get(0).type, getValues(atomList)));

		}
		for (Entry<String, List<FilterAtom>> entry : filterNameToFilterMapAND.entrySet()) {
			List<FilterAtom> atomList = entry.getValue();
			filterStrings.add(new FilterEntry(atomList.get(0).type, getValues(atomList)));
		}
		return filterStrings;
	}

	private List<String> getValues(List<FilterAtom> atomList) {
		return atomList.stream().map(a -> a.getValueString()).collect(Collectors.toList());
	}

	public record FilterEntry(BSimFilterType filterType, List<String> values) {/**/}

}
