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
package ghidra.program.model.data.ISF;

import java.util.Map;

public class IsfWinPDB implements IsfObject {

	public String GUID;
	public Integer age;
	public String database;
	public Integer machine_type;

	public IsfWinPDB(Map<String, String> metaData) {
		GUID = metaData.get("PDB GUID");
		age = Integer.valueOf(metaData.get("PDB Age"));
		database = metaData.get("PDB File");
		machine_type = 0; //metaData.get("PDB Version")); //?
	}

}
