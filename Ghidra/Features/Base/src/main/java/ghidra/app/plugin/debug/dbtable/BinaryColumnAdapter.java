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

import db.BinaryField;
import db.DBRecord;

public class BinaryColumnAdapter extends AbstractColumnAdapter {

	@Override
	Class<?> getValueClass() {
		return String.class;
	}

	@Override
	Object getKeyValue(DBRecord rec) {
		byte[] bytes = ((BinaryField) rec.getKeyField()).getBinaryData();
		StringBuffer buf = new StringBuffer("  byte[" + bytes.length + "] = ");
		if (bytes.length > 0) {
			int len = Math.min(bytes.length, 20);
			buf.append(bytes[0]);
			for (int i = 1; i < len; i++) {
				buf.append(",");
				buf.append(bytes[i]);
			}
			if (bytes.length > 20) {
				buf.append("...");
			}
		}
		return buf.toString();
	}

	@Override
	Object getValue(DBRecord rec, int col) {
		byte[] bytes = rec.getBinaryData(col);
		if (bytes == null) {
			return "null";
		}
		StringBuffer buf = new StringBuffer("  byte[" + bytes.length + "] = ");
		if (bytes.length > 0) {
			int len = Math.min(bytes.length, 20);
			String str = getByteString(bytes[0]);
			buf.append(str);
			for (int i = 1; i < len; i++) {
				buf.append(",");
				buf.append(getByteString(bytes[i]));
			}
			if (bytes.length > 20) {
				buf.append("...");
			}
		}
		return buf.toString();
	}

}
