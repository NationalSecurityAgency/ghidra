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
package agent.dbgmodel.impl.dbgmodel.bridge;

import java.util.*;

import com.sun.jna.WString;
import com.sun.jna.platform.win32.Variant.VARIANT;

import agent.dbgeng.dbgeng.DebugClient;
import agent.dbgeng.dbgeng.DebugModule;
import agent.dbgmodel.dbgmodel.bridge.HostDataModelAccess;
import agent.dbgmodel.dbgmodel.datamodel.DataModelManager1;
import agent.dbgmodel.dbgmodel.debughost.*;
import agent.dbgmodel.dbgmodel.main.ModelObject;
import agent.dbgmodel.jna.dbgmodel.DbgModelNative.ModelObjectKind;
import ghidra.dbg.util.PathUtils;
import ghidra.util.Msg;

public class HDMAUtil {

	private DebugClient client;
	private HostDataModelAccess access;

	public HDMAUtil(HostDataModelAccess access) {
		this.access = access;
		this.client = access.getClient();
	}

	public DataModelManager1 getManager() {
		return access.getManager();
	}

	public DebugHost getHost() {
		return access.getHost();
	}

	public ModelObject getRootNamespace() {
		ModelObject rootNamespace = getManager().getRootNamespace();
		if (rootNamespace == null) {
			Msg.debug(this, "resetting HostDataModelAccess manager/host " + access);
			access.getDataModel();
			rootNamespace = getManager().getRootNamespace();
		}
		return rootNamespace;
	}

	public DebugHostContext getCurrentContext() {
		return getHost().getCurrentContext();
	}

	public ModelObject getSessionOf(DebugHostContext obj) {
		return getRootNamespace().getKeyValue("Debugger").getKeyValue("Sessions");//[obj]
	}

	public ModelObject getProcessOf(DebugHostContext obj) {
		return getSessionOf(obj).getKeyValue("Processes");//[obj]
	}

	public ModelObject getThreadOf(DebugHostContext obj) {
		return getProcessOf(obj).getKeyValue("Threads");//[obj]
	}

	public VARIANT string2variant(String id) {
		Integer decode = id == null ? 0 : Integer.decode(id);
		return new VARIANT(decode);
	}

	public Map<String, ModelObject> getAttributes(List<String> path) {
		ModelObject target = getTerminalModelObject(path);
		if (target == null) {
			//System.err.println("(A) Null target for path=" + path);
			return new HashMap<String, ModelObject>();
		}
		ModelObjectKind kind = target.getKind();
		if (kind.equals(ModelObjectKind.OBJECT_ERROR)) {
			HashMap<String, ModelObject> map = new HashMap<String, ModelObject>();
			map.put("ERROR", target);
			return map;
		}
		if (kind.equals(ModelObjectKind.OBJECT_INTRINSIC) ||
			kind.equals(ModelObjectKind.OBJECT_TARGET_OBJECT) ||
			kind.equals(ModelObjectKind.OBJECT_TARGET_OBJECT_REFERENCE)) {
			Map<String, ModelObject> map = target.getRawValueMap();
			if (!map.isEmpty()) {
				return map;
			}
		}
		return target.getKeyValueMap();
	}

	public List<ModelObject> getElements(List<String> path) {
		ModelObject target = getTerminalModelObject(path);
		if (target == null) {
			//System.err.println("(C) Null target for path=" + path);
			return new ArrayList<ModelObject>();
		}
		ModelObjectKind kind = target.getKind();
		if (kind.equals(ModelObjectKind.OBJECT_ERROR)) {
			List<ModelObject> list = new ArrayList<ModelObject>();
			list.add(target);
			return list;
		}
		return target.getElements();
	}

	public ModelObject getMethod(List<String> path) {
		DebugHostEvaluator2 eval = getHost().asEvaluator();
		DebugHostContext context = getHost().getCurrentContext();
		List<String> npath = PathUtils.parent(path);
		int last = path.size() - 1;
		String cmd = path.get(last);
		ModelObject parentModel = getTerminalModelObject(npath);
		return eval.evaluateExtendedExpression(context, new WString(cmd), parentModel);
	}

	public ModelObject getTerminalModelObject(List<String> path) {
		//System.err.println(path);
		ModelObject target = getRootNamespace();
		boolean found;
		for (String str : path) {
			//System.err.println(":" + str);
			String indexStr = null;
			found = false;
			if (str.endsWith(")")) {
				target = evaluatePredicate(target, str);
				if (target.getKind().equals(ModelObjectKind.OBJECT_ERROR)) {
					return target;
				}
			}
			if (str.endsWith("]")) {
				indexStr = str.substring(str.indexOf("[") + 1, str.indexOf("]"));
				str = str.substring(0, str.indexOf("["));
			}
			Map<String, ModelObject> keyMap = target.getKeyValueMap();
			if (keyMap.containsKey(str)) {
				target = keyMap.get(str);
				found = true;
			}
			else {
				Map<String, ModelObject> rawMap = target.getRawValueMap();
				if (rawMap.containsKey(str)) {
					target = rawMap.get(str);
					found = true;
				}
			}
			if (indexStr != null) {
				List<ModelObject> children = target.getElements();
				for (ModelObject child : children) {
					if (indexStr.equals(child.getSearchKey())) {
						target = child;
						found = true;
					}
				}
			}
			if (found == false) {
				return null;
			}
		}
		return target;
	}

	private ModelObject evaluatePredicate(ModelObject target, String call) {
		DebugHostEvaluator2 eval = getHost().asEvaluator();
		DebugHostContext context = getHost().getCurrentContext();
		return eval.evaluateExtendedExpression(context, new WString(call), target);
	}

	public ModelObject getSession(String id) {
		return getRootNamespace().getKeyValue("Debugger").getKeyValue("Sessions");
	}

	public ModelObject getProcess(ModelObject session, String id) {
		ModelObject processes = session.getKeyValue("Processes");
		return processes.getChild(getManager(), string2variant(id));
	}

	public ModelObject getThread(ModelObject process, String id) {
		ModelObject threads = process.getKeyValue("Threads");
		return threads.getChild(getManager(), string2variant(id));
	}

	public ModelObject getSettings() {
		return getRootNamespace().getKeyValue("Debugger").getKeyValue("Settings");
	}

	public ModelObject getVariables() {
		return getRootNamespace().getKeyValue("Debugger")
				.getKeyValue("State")
				.getKeyValue("DebuggerVariables");
	}

	public ModelObject getCurrentSession() {
		return getVariables().getKeyValue("cursession");
	}

	public ModelObject getCurrentProcess() {
		return getVariables().getKeyValue("curprocess");
	}

	public ModelObject getCurrentThread() {
		return getVariables().getKeyValue("curthread");
	}

	public ModelObject getCurrentStack() {
		return getCurrentThread().getKeyValue("Stack");
	}

	public ModelObject getCurrentFrame() {
		return getVariables().getKeyValue("curframe");
	}

	public List<ModelObject> getCurrentModuleList() {
		ModelObject process = getCurrentProcess();
		ModelObject modules = process.getKeyValue("Modules");
		return modules.getElements();
	}

	public List<DebugModule> getModuleList() {
		DebugHostSymbols symbols = getHost().asSymbols();
		DebugHostSymbolEnumerator enumerator = symbols.enumerateModules(getCurrentContext());
		List<DebugModule> modules = new ArrayList<DebugModule>();
		DebugHostSymbol1 next;
		int index = 0;
		while ((next = enumerator.getNext()) != null) {
			DebugHostModule1 module = next.asModule();
			String name = module.getName();
			//BSTR imageName = module.getImageName(true);
			//LOCATION base = module.getBaseLocation();
			//long baseAddress = base.Offset.longValue();
			DebugModule debugModule = client.getSymbols().getModuleByModuleName(name, index++);
			//DebugModule debugModule = new DbgModelModule(name, baseAddress, index++);
			modules.add(debugModule);
		}
		return modules;
	}

	public List<ModelObject> getRunningProcesses(String id) {
		ModelObject session = getSession(id);
		ModelObject processes = session.getKeyValue("Processes");
		return processes.getElements();
	}

	public List<ModelObject> getRunningThreads(ModelObject session, String id) {
		ModelObject process = getProcess(session, id);
		ModelObject threads = process.getKeyValue("Threads");
		return threads.getElements();
	}

	public ModelObject getProcessDescription(String sid, int systemId) {
		ModelObject session = getSession(sid);
		return getProcess(session, Integer.toHexString(systemId));
	}

	public void setCurrentProcess(ModelObject context, String id) {
		VARIANT v = new VARIANT(id);
		context.switchTo(getManager(), v);
	}

	public void setCurrentThread(ModelObject context, String id) {
		VARIANT v = new VARIANT(id);
		context.switchTo(getManager(), v);
	}

	public String getCtlId(ModelObject object) {
		ModelObject value = object.getKeyValue("Id");
		return value == null ? "" : value.getValueString();
	}

}
