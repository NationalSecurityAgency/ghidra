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

import db.DBRecord;
import db.ShortField;

public class ShortColumnAdapter extends AbstractColumnAdapter {

	@Override
	Class<?> getValueClass() {
		return Short.class;
	}

	@Override
	Object getKeyValue(DBRecord rec) {
		return new Short(((ShortField) rec.getKeyField()).getShortValue());
	}

	@Override
	Object getValue(DBRecord rec, int col) {
		return new Short(rec.getShortValue(col));
	}

}
