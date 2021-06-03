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
package ghidra.util.database;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.ArrayUtils;

import db.*;

public class SchemaBuilder {
	public static int getColumnIndex(Schema schema, String name) {
		return ArrayUtils.indexOf(schema.getFieldNames(), name);
	}

	private int version = 0;
	private String keyFieldName = "Key";
	private Class<? extends Field> keyFieldClass = LongField.class;
	private List<String> fieldNames = new ArrayList<>();
	private List<Class<? extends Field>> fieldClasses = new ArrayList<>();

	public SchemaBuilder version(@SuppressWarnings("hiding") int version) {
		this.version = version;
		return this;
	}

	public SchemaBuilder keyField(String name, Class<? extends Field> cls) {
		this.keyFieldName = name;
		this.keyFieldClass = cls;
		return this;
	}

	public SchemaBuilder field(String name, Class<? extends Field> cls) {
		this.fieldNames.add(name);
		this.fieldClasses.add(cls);
		return this;
	}

	public int fieldCount() {
		return fieldNames.size();
	}

	public Schema build() {
		return new Schema(version, keyFieldClass, keyFieldName,
			fieldClasses.toArray(new Class[fieldClasses.size()]),
			fieldNames.toArray(new String[fieldNames.size()]));
	}
}
