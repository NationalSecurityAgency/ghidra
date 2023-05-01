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

public class IsfWinPE implements IsfObject {

	public Integer build;
	public Integer major;
	public Integer minor;
	public Integer revision;

	public IsfWinPE(Map<String, String> metaData) {
		String data = metaData.get("PE Property[ProductVersion]");
		String[] quad = data.split("\\.");
		build = Integer.valueOf(quad[3]);
		major = Integer.valueOf(quad[0]);
		minor = Integer.valueOf(quad[1]);
		revision = Integer.valueOf(quad[2]);
	}

}
