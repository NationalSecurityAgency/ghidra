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
package sarif.handlers;

import com.contrastsecurity.sarif.Run;

import ghidra.util.classfinder.ExtensionPoint;
import sarif.SarifController;
import sarif.model.SarifDataFrame;

abstract public class SarifRunHandler implements ExtensionPoint {	
	
	protected SarifDataFrame df;
	protected SarifController controller;
	protected Run run;

	public abstract String getKey();

	public boolean isEnabled() {
		return true;
	}
	
	public void handle(SarifDataFrame df, Run run) {
		this.df = df;
		this.controller = df.getController();
		this.run = run;
		parse();
	}
	
	protected abstract Object parse();

}
