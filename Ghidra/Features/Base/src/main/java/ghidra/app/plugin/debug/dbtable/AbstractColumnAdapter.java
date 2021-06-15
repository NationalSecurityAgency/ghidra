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

abstract class AbstractColumnAdapter {

	abstract Class<?> getValueClass();

	abstract Object getKeyValue(DBRecord rec);

	abstract Object getValue(DBRecord rec, int col);

	protected String getByteString(byte b) {
		String str = Integer.toHexString(b);
		if (str.length() > 2) {
			str = str.substring(str.length() - 2);
		}
		return "0x" + str;
	}

//	private String format(long l, int size) {
//		String hex = Long.toHexString(l);
//		if (hex.length() > size) {
//			hex = hex.substring(hex.length()-size);
//		}
//		else if (hex.length() < size) {
//			StringBuffer b = new StringBuffer(20);
//			for(int i=hex.length();i<size;i++) {
//				b.append("");
//			}
//			b.append(hex);
//			hex = b.toString();
//		}
//		
//		return hex;
//	}
}
