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

import db.DBConstants;

public enum DBOpenMode {
	CREATE(DBConstants.CREATE),
	UPDATE(DBConstants.UPDATE),
	READ_ONLY(DBConstants.READ_ONLY),
	UPGRADE(DBConstants.UPGRADE);

	private final int openMode;

	private DBOpenMode(int openMode) {
		this.openMode = openMode;
	}

	public int toInteger() {
		return openMode;
	}
}
