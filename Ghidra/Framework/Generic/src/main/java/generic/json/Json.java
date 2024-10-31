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

import java.lang.reflect.AccessibleObject;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

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
			this.setFieldNameValueSeparator(": ");

			this.setNullText("null");

			this.setSummaryObjectStartText("\"<");
			this.setSummaryObjectEndText(">\"");

			this.setSizeStartText("\"<size=");
			this.setSizeEndText(">\"");
		}
	}

	/**
	 * A {@link ToStringStyle} inspired by {@link ToStringStyle#JSON_STYLE} that places
	 * object fields all on one line, with Json style formatting.
	 */
	public static class JsonWithFlatToStringStyle extends ToStringStyle {

		private JsonWithFlatToStringStyle() {
			this.setUseClassName(false);
			this.setUseIdentityHashCode(false);

			this.setContentStart("{ ");
			this.setContentEnd(" }");

			this.setArrayStart("[");
			this.setArrayEnd("]");

			this.setFieldSeparator(", ");
			this.setFieldNameValueSeparator(": ");

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
	 * <p>
	 * The returned string is formatted for pretty printing using whitespace, such as tabs and 
	 * newlines.
	 * 
	 * @param o the object
	 * @return the string
	 */
	public static String toString(Object o) {
		return ToStringBuilder.reflectionToString(o, Json.WITH_NEWLINES);
	}

	/**
	 * Creates a Json string representation of the given object and all of its fields.
	 * <p>
	 * The returned string is formatted without newlines for better use in logging.
	 * 
	 * @param o the object
	 * @return the string
	 */
	public static String toStringFlat(Object o) {
		return ToStringBuilder.reflectionToString(o, new JsonWithFlatToStringStyle());
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
		ReflectionToStringBuilder builder = new ReflectionToStringBuilder(o, Json.WITH_NEWLINES);
		builder.setExcludeFieldNames(excludedFields);
		return builder.toString();
	}

	private static class InclusiveReflectionToStringBuilder extends ReflectionToStringBuilder {

		private String[] includedNames = new String[0];

		public InclusiveReflectionToStringBuilder(Object object) {
			super(object, WITH_NEWLINES);
		}

		@Override
		protected boolean accept(Field field) {
			if (!super.accept(field)) {
				return false;
			}

			if (includedNames.length == 0) {
				return true; // this implies a programming error
			}

			String fieldName = field.getName();
			for (String name : includedNames) {
				if (fieldName.equals(name)) {
					return true;
				}
			}

			return false;
		}

		// Overridden to control the order the field are listed.  The parent class sorts by name; we
		// want output in the order specified by the user.
		@Override
		protected void appendFieldsIn(final Class<?> clazz) {
			if (clazz.isArray()) {
				super.appendFieldsIn(clazz);
				return;
			}

			if (includedNames.length == 0) {
				super.appendFieldsIn(clazz);
				return;
			}

			Field[] fields = clazz.getDeclaredFields();
			AccessibleObject.setAccessible(fields, true);
			Map<String, Field> fieldsByName =
				Arrays.stream(fields).collect(Collectors.toMap(f -> f.getName(), f -> f));
			for (String name : includedNames) {

				Field field = fieldsByName.get(name);
				if (field == null) {
					continue;
				}

				if (accept(field)) {
					try {
						// Field.get(Object) creates wrappers objects for primitive types.
						Object fieldValue = this.getValue(field);
						if (!isExcludeNullValues() || fieldValue != null) {
							this.append(name, fieldValue,
								!field.isAnnotationPresent(ToStringSummary.class));
						}
					}
					catch (IllegalAccessException ex) {
						throw new InternalError(
							"Unexpected IllegalAccessException: " + ex.getMessage());
					}
				}
			}
		}

		/**
		 * Sets the names to be included
		 * @param includeFieldNamesParam the names
		 * @return this builder
		 */
		public ReflectionToStringBuilder setIncludeFieldNames(String... includeFieldNamesParam) {
			if (includeFieldNamesParam == null) {
				this.includedNames = new String[0];
			}
			else {
				this.includedNames = includeFieldNamesParam;
			}
			return this;
		}
	}
}
