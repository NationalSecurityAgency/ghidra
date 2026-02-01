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
package ghidra.features.bsim.gui.filters;

import java.io.IOException;
import java.io.Writer;
import java.sql.SQLException;
import java.util.*;

import ghidra.features.bsim.query.client.IDSQLResolution;
import ghidra.features.bsim.query.client.SQLEffects;
import ghidra.features.bsim.query.description.DatabaseInformation;
import ghidra.features.bsim.query.description.ExecutableRecord;
import ghidra.features.bsim.query.elastic.*;
import ghidra.features.bsim.query.protocol.FilterAtom;
import ghidra.xml.XmlElement;
import utility.function.Callback;

/** 
 * The base class for BSim filter types. Each filter type represents a different filter criteria 
 * that can be applied to a BSim Search query. They have a human readable description and a way
 * to convert string values for the filter into SQL queries.
 */
public abstract class BSimFilterType implements Comparable<BSimFilterType> {
	private static List<BSimFilterType> basis = null;
	public static BSimFilterType BLANK = new BlankBSimFilterType();
	protected String label; // The description of this element in gui menus
	protected String xmlval; // Tag name for serialization of filters
	protected String hint; // The text that will show in the gui input field as a 'hint'

	/**
	 * 
	 * @param label is the name used for display
	 * @param xmlval is the name used for XML serialization
	 * @param hint is the pop-up menu hint
	 */
	public BSimFilterType(String label, String xmlval, String hint) {
		this.label = label;
		this.xmlval = xmlval;
		this.hint = hint;
	}

	@Override
	public String toString() {
		return label;
	}

	@Override
	public int hashCode() {
		return Objects.hash(label);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		BSimFilterType other = (BSimFilterType) obj;
		return Objects.equals(hint, other.hint) && Objects.equals(label, other.label) &&
			Objects.equals(xmlval, other.xmlval);
	}

	@Override
	public int compareTo(BSimFilterType op2) {
		return label.compareTo(op2.label);
	}

	/**
	 * @return the tag name for serialization
	 */
	public String getXmlValue() {
		return xmlval;
	}

	/**
	 * @return the hint text
	 */
	public String getHint() {
		return hint;
	}

	/**
	 * @return true if this is a filter element based on callgraph information of functions
	 */
	public boolean isChildFilter() {
		return false;
	}

	/**
	 * @return true if this is a "blank" filter (i.e. an unused element within a gui)
	 */
	public boolean isBlank() {
		return false;
	}

	/**
	 * @return true if any id's relevant to this filter must be resolved relative to the local ColumnDatabase
	 */
	public boolean isLocal() {
		return true;
	}

	/**
	 * @return true if multiple filters of this type are allowed.
	 */
	public boolean isMultipleEntryAllowed() {
		return true;
	}

	/**
	 * @return true if multiple filters of this type should be OR'd. AND them otherwise.
	 */
	public boolean orMultipleEntries() {
		return true;
	}

	/**
	 * Save XML attributes corresponding to this template
	 * @param fwrite is the output stream
	 * @throws IOException for problems writing to the stream
	 */
	public void saveXml(Writer fwrite) throws IOException {
		fwrite.append(" type=\"").append(xmlval).append('\"');
	}

	/**
	 * Construct a record describing the column id's that might need to be recovered before this filter
	 * element can be converted to an SQL clause
	 * @param atom is the specific FilterAtom to generate the record for
	 * @return the IDSQLResolution record or null if no ids need to be recovered
	 */
	public abstract IDSQLResolution generateIDSQLResolution(FilterAtom atom);

	/**
	 * Construct a record describing the document id's that might be needed before this filter
	 * element can be converted to an Elasticsearch filter script clause
	 * @param atom is the specific FilterAtom to generate the record for
	 * @return the record or null if no ids need to be recovered
	 */
	public IDElasticResolution generateIDElasticResolution(FilterAtom atom) {
		return null;
	}

	/**
	 * Gather all pieces to successfully convert this filter element into an SQL clause
	 * @param effect is SQLEffects container for this filter elements pieces and others
	 * @param atom holds the values for a particular instantiation of this filter element
	 * @param resolution is the IDResolution containing relevant row ids for the filter, which must have been precalculated
	 * @throws SQLException for errors building the SQL clause
	 */
	public abstract void gatherSQLEffect(SQLEffects effect, FilterAtom atom,
		IDSQLResolution resolution) throws SQLException;

	/**
	 * Gather pieces necessary to emit this filter as part of an elasticsearch query document
	 * @param effect is the ElasticEffects container holding the pieces
	 * @param atom holds the values for a particular instantiation of this filter element
	 * @param resolution contains relevant ids for the filter, which must have been precalculated
	 * @throws ElasticException for errors building the JSON subdocument
	 */
	public abstract void gatherElasticEffect(ElasticEffects effect, FilterAtom atom,
		IDElasticResolution resolution) throws ElasticException;

	/**
	 * Given (multiple) clauses for a single filter type, combine into a single SQL where clause
	 * @param subClauses is the list of SQL clauses
	 * @return the combined clause
	 */
	public String buildSQLCombinedClause(List<String> subClauses) {
		String appender = orMultipleEntries() ? " OR " : " AND "; // OR or AND things together
		StringBuilder orClause = new StringBuilder();
		orClause.append('(');
		boolean printAppender = false;
		for (String str : subClauses) {
			if (printAppender) {
				orClause.append(appender);
			}
			orClause.append(str);
			printAppender = true;
		}
		orClause.append(')');
		return orClause.toString();
	}

	/**
	 * Given (multiple) clauses for a single filter type, combine into a single elasticsearch script conditional
	 * @param subClauses is the list of script clauses
	 * @return the combined clause
	 */
	public String buildElasticCombinedClause(List<String> subClauses) {
		String appender = orMultipleEntries() ? " || " : " && ";	// OR or AND things together
		StringBuilder clause = new StringBuilder();
		clause.append('(');
		boolean printAppender = false;
		for (String str : subClauses) {
			if (printAppender) {
				clause.append(appender);
			}
			clause.append(str);
			printAppender = true;
		}
		clause.append(')');
		return clause.toString();
	}

	public BSimValueEditor getEditor(List<String> initialValues, Callback listener) {
		return new StringBSimValueEditor(this, initialValues, listener);
	}

	/**
	 * Evaluate this filter for a specific ExecutableRecord and a specific filter -value-
	 * @param rec is the ExecutableRecord to filter against
	 * @param value is the String value for an instantiated filter
	 * @return true if this element would allow the ExecutableRecord to pass the filter
	 */
	public abstract boolean evaluate(ExecutableRecord rec, String value);

	/**
	 * Tests if the given string is a valid value for this filter type.
	 * @param value the value to test
	 * @return true if the given string is valid for this filter
	 */
	public boolean isValidValue(String value) {
		return value != null && !value.isBlank();
	}

	/**
	 * Returns a normalized version of the given value for this filter.
	 * @param value the value to be normalized
	 * @return a normalized version of the given value for this filter
	 */
	public String normalizeValue(String value) {
		return value.trim();
	}

	/**
	 * @return the Blank FilterTemplate
	 */
	public static BSimFilterType getBlank() {
		buildFilterBasis();
		return basis.get(0);
	}

	public static List<BSimFilterType> getBaseFilters() {
		buildFilterBasis();
		return basis;
	}

	/**
	 * Convenience function for deserializing FilterTemplates
	 * @param el is the tag to deserialize
	 * @return the deserialized FilterTemplate
	 */
	public static BSimFilterType nameToType(XmlElement el) {
		String attr = el.getAttribute("type");
		buildFilterBasis();			// Make sure generic filter list is built
		for (BSimFilterType cur : basis) {
			if (cur.xmlval.equals(attr)) {
				return cur;
			}
		}
		if (attr.equals(ExecutableNameBSimFilterType.XML_VALUE)) {
			String subattr = el.getAttribute("subtype");
			return new ExecutableCategoryBSimFilterType(subattr);
		}
		else if (attr.equals(NotExecutableCategoryBSimFilterType.XML_VALUE)) {
			String subattr = el.getAttribute("subtype");
			return new NotExecutableCategoryBSimFilterType(subattr);
		}
		else if (attr.equals(FunctionTagBSimFilterType.XML_VALUE)) {
			String tagName = el.getAttribute("tagname");
			int flag = Integer.decode(el.getAttribute("flag"));
			return new FunctionTagBSimFilterType(tagName, flag);
		}
		return basis.get(0);		// Default template
	}

	/**
	 * Build the static set of basic FilterTemplates
	 */
	private static void buildFilterBasis() {
		if (basis != null) {
			return;		// Already built
		}
		basis = new ArrayList<BSimFilterType>();
		basis.add(new BlankBSimFilterType());
		basis.add(new ExecutableNameBSimFilterType());
		basis.add(new NotExecutableNameBSimFilterType());
		basis.add(new Md5BSimFilterType());
		basis.add(new NotMd5BSimFilterType());
		basis.add(new ArchitectureBSimFilterType());
		basis.add(new NotArchitectureBSimFilterType());
		basis.add(new CompilerBSimFilterType());
		basis.add(new NotCompilerBSimFilterType());
		basis.add(new PathStartsBSimFilterType());
		basis.add(new HasNamedChildBSimFilterType());
	}

	/**
	 * Generate a possibly restricted/extended set of FilterTemplates
	 * @param info is database information which informs about which filters to create
	 * @param includeChildFilter toggles whether or not ChildFilters should be included in this particular set
	 * @return the list of filter templates
	 */
	public static List<BSimFilterType> generateBsimFilters(DatabaseInformation info,
		boolean includeChildFilter) {
		List<BSimFilterType> resFilters = new ArrayList<BSimFilterType>();
		buildFilterBasis();

		for (BSimFilterType template : basis) {
			if (template.isChildFilter()) {
				if (!includeChildFilter || (info != null && !info.trackcallgraph)) {
					continue;
				}
			}
			resFilters.add(template);
		}

		// If the database explicitly names the date column for the database,
		// this OVERRIDES the default "Ingest Date" column.
		// There is only room for one date in the table row
		if (info != null && info.dateColumnName != null && !info.dateColumnName.isEmpty()) {
			DateEarlierBSimFilterType earlierTemplate =
				new DateEarlierBSimFilterType(info.dateColumnName); // Create customized date filters
			DateLaterBSimFilterType laterTemplate =
				new DateLaterBSimFilterType(info.dateColumnName);
			resFilters.add(earlierTemplate); // Add customized filters to list
			resFilters.add(laterTemplate);
		}
		else {
			// Otherwise, we add default date filters to list
			DateEarlierBSimFilterType filt = new DateEarlierBSimFilterType("Ingest Date");
			resFilters.add(filt);
			DateLaterBSimFilterType filt2 = new DateLaterBSimFilterType("Ingest Date");
			resFilters.add(filt2);
		}
		if (info != null && info.execats != null) {
			for (String element : info.execats) {
				ExecutableCategoryBSimFilterType filt =
					new ExecutableCategoryBSimFilterType(element);
				resFilters.add(filt);
				NotExecutableCategoryBSimFilterType filt2 =
					new NotExecutableCategoryBSimFilterType(element);
				resFilters.add(filt2);
			}
		}
		FunctionTagBSimFilterType filtFuncTag;
		filtFuncTag = new FunctionTagBSimFilterType("KNOWN_LIBRARY",
			FunctionTagBSimFilterType.KNOWN_LIBRARY_MASK);
		resFilters.add(filtFuncTag);
		filtFuncTag = new FunctionTagBSimFilterType("HAS_UNIMPLEMENTED",
			FunctionTagBSimFilterType.HAS_UNIMPLEMENTED_MASK);
		resFilters.add(filtFuncTag);
		filtFuncTag = new FunctionTagBSimFilterType("HAS_BADDATA",
			FunctionTagBSimFilterType.HAS_BADDATA_MASK);
		resFilters.add(filtFuncTag);
		if (info != null && info.functionTags != null) {
			int flag = 1;
			flag <<= FunctionTagBSimFilterType.RESERVED_BITS; // First bits are reserved
			for (String element : info.functionTags) {
				filtFuncTag = new FunctionTagBSimFilterType(element, flag);
				resFilters.add(filtFuncTag);
				flag <<= 1;
			}
		}
		return resFilters;
	}

	public String getLabel() {
		return label;
	}
}
