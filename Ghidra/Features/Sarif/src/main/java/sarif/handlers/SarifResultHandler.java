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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.contrastsecurity.sarif.PropertyBag;
import com.contrastsecurity.sarif.Result;
import com.contrastsecurity.sarif.Run;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.program.util.ProgramTask;
import ghidra.util.classfinder.ExtensionPoint;
import ghidra.util.task.TaskLauncher;
import sarif.SarifController;
import sarif.model.SarifDataFrame;
import sarif.view.SarifResultsTableProvider;

abstract public class SarifResultHandler implements ExtensionPoint {	
	
	protected List<String> headers = new ArrayList<>();
	protected SarifDataFrame df;
	protected SarifController controller;
	protected Run run;
	protected Result result;
	protected SarifResultsTableProvider provider;

	public abstract String getKey();

	public boolean isEnabled() {
		return true;
	}
	
	public void handle(SarifDataFrame df, Run run, Result result, Map<String, Object> map) {
		this.df = df;
		this.controller = df.getController();
		this.run = run;
		this.result = result;
		Object res = parse();
		if (res != null) {	
			map.put(getKey(), res);
		}
	}
	
	protected abstract Object parse();

	public String getActionName() {
		return null;
	}
	
	protected Object getProperty(String key) {
		PropertyBag properties = result.getProperties();
		if (properties == null) {
			return null;
		}
		Map<String, Object> additionalProperties = properties.getAdditionalProperties();
		if (additionalProperties == null) {
			return null;
		}
		return additionalProperties.get(key);
	}
	
	public ProgramTask getTask(SarifResultsTableProvider provider) {
		return null;
	}
	
	public DockingAction createAction(SarifResultsTableProvider provider) {
		this.provider = provider;
		DockingAction rightClick = new DockingAction(getActionName(), getKey()) {
			@Override
			public void actionPerformed(ActionContext context) {
				ProgramTask task = getTask(provider);
				TaskLauncher.launch(task);
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return true;
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return true;
			}
		};
		rightClick.setPopupMenuData(new MenuData(new String[] { getActionName() }));
		return rightClick;
	}
}
