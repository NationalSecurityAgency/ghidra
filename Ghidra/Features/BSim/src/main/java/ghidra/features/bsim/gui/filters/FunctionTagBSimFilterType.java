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
import java.util.List;
import java.util.Objects;

import ghidra.features.bsim.query.client.IDSQLResolution;
import ghidra.features.bsim.query.client.SQLEffects;
import ghidra.features.bsim.query.description.DatabaseInformation;
import ghidra.features.bsim.query.description.ExecutableRecord;
import ghidra.features.bsim.query.elastic.*;
import ghidra.features.bsim.query.facade.SimilarFunctionQueryService;
import ghidra.features.bsim.query.protocol.FilterAtom;
import ghidra.util.exception.InvalidInputException;
import utility.function.Callback;

/**
 * A BsimFilterType for filtering functions based on specific function tag values.
 */
public class FunctionTagBSimFilterType extends BSimFilterType {
	public static final String XML_VALUE = "functiontag";
	public static int RESERVED_BITS = 3;
	public static int MAX_TAG_COUNT = 32 - RESERVED_BITS;
	public static int KNOWN_LIBRARY_MASK = 1;
	public static int HAS_UNIMPLEMENTED_MASK = 2;
	public static int HAS_BADDATA_MASK = 4;
	private String tagName; // Particular tag being tested
	private int flag; // bit position of the boolean value

	/**
	 * Creates a new function tag filter.
	 * 
	 * @param tagName the tag name
	 * @param flag the bit position of this flag
	 */
	public FunctionTagBSimFilterType(String tagName, int flag) {
		super("Function tagged as " + tagName, XML_VALUE, "function tag");
		this.tagName = tagName;
		this.flag = flag;
	}

	/**
	 * Constructor for clients who do not know what the bit flag position of this
	 * function tag is. If that's the case, this will figure it out from the
	 * given queryService object. 
	 * 
	 * @param tagName the name of the tag
	 * @param queryService query service used to retrieve tag big position
	 * @throws InvalidInputException thrown if tag does not exist
	 */
	public FunctionTagBSimFilterType(String tagName, SimilarFunctionQueryService queryService)
		throws InvalidInputException {
		super("Function tagged as " + tagName, XML_VALUE, "function tag");
		this.tagName = tagName;

		DatabaseInformation info = queryService.getDatabaseInformation();
		if (info == null) {
			throw new IllegalStateException("queryService has not been initialized");
		}
		List<String> functionTags = info.functionTags;
		if (functionTags == null) {
			throw new InvalidInputException("Function tag does not exist: " + tagName);
		}

		flag = 8;
		for (String tag : functionTags) {
			if (tag.endsWith(tagName)) {
				break;
			}
			flag = flag * 2;
		}
	}

	public int getFlag() {
		return flag;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + Objects.hash(flag, tagName);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!super.equals(obj)) {
			return false;
		}
		if (obj instanceof FunctionTagBSimFilterType t) {
			return flag == t.flag && Objects.equals(tagName, t.tagName);
		}
		return false;
	}

	@Override
	public void saveXml(Writer fwrite) throws IOException {
		super.saveXml(fwrite);
		fwrite.append(" tagname=\"").append(tagName).append('\"');
		fwrite.append(" flag=\"").append(Integer.toString(flag)).append('\"');
	}

	@Override
	public IDSQLResolution generateIDSQLResolution(FilterAtom atom) {
		return null;
	}

	@Override
	public boolean evaluate(ExecutableRecord rec, String value) {
		return true; // Not a test on executable
	}

	/**
	 * @return false, only one boolean value is allowed
	 */
	@Override
	public boolean isMultipleEntryAllowed() {
		return false;
	}

	@Override
	public void gatherSQLEffect(SQLEffects effect, FilterAtom atom, IDSQLResolution resolution)
		throws SQLException {
		effect.addFunctionFilter(flag, atom.value.equals("true"));
	}

	@Override
	public void gatherElasticEffect(ElasticEffects effect, FilterAtom atom,
		IDElasticResolution resolution) throws ElasticException {
		effect.addFunctionFilter(flag, atom.value.equals("true"));
	}

	@Override
	public String normalizeValue(String value) {
		if (value != null) {
			if (value.equals("f") || value.equals("false")) {
				return "false";
			}
			if (value.equals("t") || value.equals("true")) {
				return "true";
			}
		}
		return null;
	}

	@Override
	public boolean isValidValue(String value) {
		return normalizeValue(value) != null;
	}

	@Override
	public BSimValueEditor getEditor(List<String> initialValues, Callback listener) {
		return new BooleanBSimValueEditor(this, initialValues, listener);

	}

}
