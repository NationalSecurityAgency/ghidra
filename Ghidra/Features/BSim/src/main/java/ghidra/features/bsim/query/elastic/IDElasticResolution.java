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
package ghidra.features.bsim.query.elastic;

import ghidra.features.bsim.query.description.ExecutableRecord;

public abstract class IDElasticResolution {
	public String idString;

	public abstract void resolve(ElasticDatabase database,ExecutableRecord exe) throws ElasticException;

	public static class ExternalFunction extends IDElasticResolution {
		private String exeName;			// Name of executable containing external function
		private String funcName;		// Name of external function

		public ExternalFunction(String exe,String func) {
			exeName = exe;
			funcName = func;
			idString = null;
		}

		public void resolve(ElasticDatabase database,ExecutableRecord exe) throws ElasticException {
			if (idString == null)
				idString = database.recoverExternalFunctionId(exeName, funcName, exe.getArchitecture());
		}
	}
}
