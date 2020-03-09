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
package generic.json;

import java.lang.reflect.Field;
import java.util.Arrays;

import org.apache.commons.lang3.builder.*;

/**
 * A utility class to format strings in JSON format.   This is useful for easily generating
 * {@code toString()} representations of objects.
 */
public class Json extends ToStringStyle {

	public static final JsonWithNewlinesToStringStyle WITH_NEWLINES =
		new JsonWithNewlinesToStringStyle();

	/**
	 * A {@link ToStringStyle} inspired by {@link ToStringStyle#JSON_STYLE} that places
	 * object fields on newlines for more readability
	 */
	public static class JsonWithNewlinesToStringStyle extends ToStringStyle {

		private JsonWithNewlinesToStringStyle() {
			this.setUseClassName(false);
			this.setUseIdentityHashCode(false);

			this.setContentStart("{\n\t");
			this.setContentEnd("\n}");

			this.setArrayStart("[");
			this.setArrayEnd("]");

			this.setFieldSeparator(",\n\t");
			this.setFieldNameValueSeparator(":");

			this.setNullText("null");

			this.setSummaryObjectStartText("\"<");
			this.setSummaryObjectEndText(">\"");

			this.setSizeStartText("\"<size=");
			this.setSizeEndText(">\"");
		}
	}

	/**
	 * Creates a Json string representation of the given object and all of its fields.  To exclude
	 * some fields, call {@link #toStringExclude(Object, String...)}.  To only include particular
	 * fields, call {@link #appendToString(StringBuffer, String)}.
	 * @param o the object
	 * @return the string
	 */
	public static String toString(Object o) {
		return ToStringBuilder.reflectionToString(o, Json.WITH_NEWLINES);
	}

	/**
	 * Creates a Json string representation of the given object and the given fields
	 * @param o the object
	 * @param includFields the fields to include
	 * @return the string
	 */
	public static String toString(Object o, String... includFields) {

		InclusiveReflectionToStringBuilder builder = new InclusiveReflectionToStringBuilder(o);
		builder.setIncludeFieldNames(includFields);
		return builder.toString();
	}

	/**
	 * Creates a Json string representation of the given object and all of its fields except for
	 * those in the given exclusion list
	 * @param o the object
	 * @param excludedFields the excluded field names
	 * @return the string
	 */
	public static String toStringExclude(Object o, String... excludedFields) {
		ReflectionToStringBuilder builder = new ReflectionToStringBuilder(o,
			Json.WITH_NEWLINES);
		builder.setExcludeFieldNames(excludedFields);
		return builder.toString();
	}

	// Future: update this class to use the order of the included fields to be the printed ordered
	private static class InclusiveReflectionToStringBuilder extends ReflectionToStringBuilder {

		private String[] includedNames;

		public InclusiveReflectionToStringBuilder(Object object) {
			super(object, WITH_NEWLINES);
		}

		@Override
		protected boolean accept(Field field) {
			if (!super.accept(field)) {
				return false;
			}

			if (this.includedNames != null &&
				Arrays.binarySearch(this.includedNames, field.getName()) >= 0) {
				return true;
			}

			return false;
		}

		/**
		 * Sets the names to be included
		 * @param includeFieldNamesParam the names
		 * @return this builder
		 */
		public ReflectionToStringBuilder setIncludeFieldNames(
				final String... includeFieldNamesParam) {
			if (includeFieldNamesParam == null) {
				this.includedNames = null;
			}
			else {
				this.includedNames = includeFieldNamesParam;
				Arrays.sort(this.includedNames);
			}
			return this;
		}
	}
}
