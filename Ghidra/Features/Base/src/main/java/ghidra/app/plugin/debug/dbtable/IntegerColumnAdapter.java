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
package ghidra.app.plugin.debug.dbtable;

import db.IntField;
import db.DBRecord;

public class IntegerColumnAdapter extends AbstractColumnAdapter {

	@Override
	Class<?> getValueClass() {
		return Integer.class;
	}

	@Override
	Object getKeyValue(DBRecord rec) {
		return new Integer(((IntField) rec.getKeyField()).getIntValue());
	}

	@Override
	Object getValue(DBRecord rec, int col) {
		return new Integer(rec.getIntValue(col));
	}

}
