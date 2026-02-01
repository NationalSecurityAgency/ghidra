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
package ghidra.features.bsim.query.file;

import java.util.HashMap;
import java.util.Map;

import ghidra.features.bsim.query.BSimServerInfo;

public class BSimVectorStoreManager {

	private static Map<BSimServerInfo, VectorStore> vectorStoreMap = new HashMap<>();

	public static synchronized VectorStore getVectorStore(BSimServerInfo serverInfo) {
		return vectorStoreMap.computeIfAbsent(serverInfo, info -> new VectorStore(info));
	}

	public static synchronized void remove(BSimServerInfo serverInfo) {
		vectorStoreMap.remove(serverInfo);
	}

}
