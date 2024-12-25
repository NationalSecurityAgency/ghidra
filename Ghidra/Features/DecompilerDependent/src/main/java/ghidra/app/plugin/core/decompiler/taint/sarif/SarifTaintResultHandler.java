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
package ghidra.app.plugin.core.decompiler.taint.sarif;

import java.util.*;
import java.util.Map.Entry;

import com.contrastsecurity.sarif.*;

import docking.ActionContext;
import docking.action.*;
import ghidra.app.plugin.core.decompiler.taint.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.util.ProgramTask;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import resources.Icons;
import sarif.SarifUtils;
import sarif.handlers.SarifResultHandler;
import sarif.model.SarifDataFrame;
import sarif.view.SarifResultsTableProvider;

public class SarifTaintResultHandler extends SarifResultHandler {

	@Override
	public String getKey() {
		return "Address";
	}

	@Override
	public boolean isEnabled(SarifDataFrame dframe) {
		return dframe.getToolID().equals(AbstractTaintState.ENGINE_NAME);
	}

	@Override
	public void handle(SarifDataFrame dframe, Run run, Result result, Map<String, Object> map) {
		this.df = dframe;
		this.controller = df.getController();

		this.run = run;
		this.result = result;

		String ruleId = result.getRuleId();
		if (ruleId == null || ruleId.equals("C0001")) {
			return;
		}
		map.put("type", TaintRule.fromRuleId(ruleId));
		// TODO: this is a bit weak
		String label = "UNSPECIFIED";
		Message msg = result.getMessage();
		String[] parts = msg.getText().split(":");
		if (parts.length > 1) {
			label = parts[1].strip();
		}
		map.put("value", label);
		map.put("comment", result.getMessage().getText());

		List<Location> locs = result.getLocations();
		if (locs != null) {
			map.put("Locations", locs);
			populate(map, locs);
		}

		PropertyBag properties = result.getProperties();
		if (properties != null) {
			Map<String, Object> additionalProperties = properties.getAdditionalProperties();
			if (additionalProperties != null) {
				for (Entry<String, Object> entry : additionalProperties.entrySet()) {
					map.put(entry.getKey(), entry.getValue());
				}
			}
		}
	}

	@Override
	protected Object parse() {
		// UNUSED
		return null;
	}

	@Override
	public String getActionName() {
		return "Apply taint";
	}

	@Override
	public ProgramTask getTask(SarifResultsTableProvider prov) {
		return new ApplyTaintViaVarnodesTask(prov);
	}

	private void populate(Map<String, Object> map, List<Location> locs) {
		Location loc = locs.get(0);
		LogicalLocation ll = SarifUtils.getLogicalLocation(run, loc);
		if (ll != null) {
			String name = ll.getName();
			String fqname = ll.getFullyQualifiedName();
			String displayName = SarifUtils.extractDisplayName(ll);
			map.put("originalName", name);
			map.put("name", displayName);
			Address faddr = SarifUtils.extractFunctionEntryAddr(controller.getProgram(), fqname);
			if (faddr != null && faddr.getOffset() >= 0) {
				map.put("entry", faddr);
				map.put("Address", faddr);
			}
			Address addr = SarifUtils.getLocAddress(controller.getProgram(), fqname);
			if (addr != null) {
				map.put("Address", addr);

			}
			map.put("location", fqname);
			map.put("kind", ll.getKind());
			map.put("function", SarifUtils.extractFQNameFunction(fqname));
		}
	}

	@Override
	public DockingAction createAction(SarifResultsTableProvider prov) {
		this.provider = prov;
		this.isEnabled = isEnabled(provider.getDataFrame());

		DockingAction byVarnode = new DockingAction(getActionName(), getKey()) {
			@Override
			public void actionPerformed(ActionContext context) {
				ProgramTask task = getTask(provider);
				TaskLauncher.launch(task);
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return isEnabled;
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return isEnabled;
			}
		};
		byVarnode.setPopupMenuData(new MenuData(new String[] { getActionName() }));
		provider.addLocalAction(byVarnode);

		DockingAction applyAll = new DockingAction("Apply all", getKey()) {
			@Override
			public void actionPerformed(ActionContext context) {
				provider.filterTable.getTable().selectAll();
				TaskLauncher.launch(new ApplyTaintViaVarnodesTask(provider));
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return isEnabled;
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return isEnabled;
			}
		};
		applyAll.setDescription("Apply all");
		applyAll.setToolBarData(new ToolBarData(Icons.EXPAND_ALL_ICON));
		provider.addLocalAction(applyAll);

		DockingAction clearTaint = new DockingAction("Clear taint", getKey()) {
			@Override
			public void actionPerformed(ActionContext context) {
				TaskLauncher.launch(new ClearTaintTask(provider));
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return isEnabled;
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return isEnabled;
			}
		};
		clearTaint.setPopupMenuData(new MenuData(new String[] { "Clear taint" }));

		return clearTaint;
	}

	private class ApplyTaintViaVarnodesTask extends ProgramTask {

		private SarifResultsTableProvider tableProvider;

		protected ApplyTaintViaVarnodesTask(SarifResultsTableProvider provider) {
			super(provider.getController().getProgram(), "ApplyTaintViaVarnodesTask", true, true,
				true);
			this.tableProvider = provider;
		}

		@Override
		protected void doRun(TaskMonitor monitor) {
			int[] selected = tableProvider.filterTable.getTable().getSelectedRows();
			Map<Address, Set<TaintQueryResult>> map = new HashMap<>();
			for (int row : selected) {
				Map<String, Object> r = tableProvider.getRow(row);
				String kind = (String) r.get("kind");
				if (kind.equals("instruction") || kind.startsWith("path ")) {
					getTaintedInstruction(map, r);
				}
				if (kind.equals("variable")) {
					getTaintedVariable(map, r);
				}
			}

			PluginTool tool = tableProvider.getController().getPlugin().getTool();
			TaintService service = tool.getService(TaintService.class);
			if (service != null) {
				service.setVarnodeMap(map, true);
			}
		}

		private void getTaintedVariable(Map<Address, Set<TaintQueryResult>> map,
				Map<String, Object> r) {
			Address faddr = (Address) r.get("entry");
			Set<TaintQueryResult> vset = getSet(map, faddr);
			vset.add(new TaintQueryResult(r));
		}

		private void getTaintedInstruction(Map<Address, Set<TaintQueryResult>> map,
				Map<String, Object> r) {
			Address faddr = (Address) r.get("entry");
			String fqname = (String) r.get("location");
			Set<TaintQueryResult> vset = getSet(map, faddr);
			String edgeId = SarifUtils.getEdge(fqname);
			if (edgeId != null) {
				String srcId = SarifUtils.getEdgeSource(edgeId);
				LogicalLocation[] srcNodes = SarifUtils.getNodeLocs(srcId);
				for (LogicalLocation lloc : srcNodes) {
					vset.add(new TaintQueryResult(r, run, lloc));
				}
				String dstId = SarifUtils.getEdgeDest(edgeId);
				LogicalLocation[] dstNodes = SarifUtils.getNodeLocs(dstId);
				for (LogicalLocation lloc : dstNodes) {
					vset.add(new TaintQueryResult(r, run, lloc));
				}
			}
		}

		private Set<TaintQueryResult> getSet(Map<Address, Set<TaintQueryResult>> map,
				Address faddr) {
			Set<TaintQueryResult> vset = map.get(faddr);
			if (vset == null) {
				vset = new HashSet<TaintQueryResult>();
				map.put(faddr, vset);
			}
			return vset;
		}

	}

	private class ClearTaintTask extends ProgramTask {

		private SarifResultsTableProvider tableProvider;

		protected ClearTaintTask(SarifResultsTableProvider provider) {
			super(provider.getController().getProgram(), "ClearTaintTask", true, true, true);
			this.tableProvider = provider;
		}

		@Override
		protected void doRun(TaskMonitor monitor) {
			int rowCount = tableProvider.filterTable.getTable().getRowCount();
			int[] selected = tableProvider.filterTable.getTable().getSelectedRows();
			PluginTool tool = tableProvider.getController().getPlugin().getTool();
			TaintService service = tool.getService(TaintService.class);
			if (service == null) {
				return;
			}
			if (selected.length == 0 || selected.length == rowCount) {
				service.clearTaint();
				return;
			}

			AddressSet set = service.getAddressSet();
			AddressSet setX = new AddressSet();
			for (AddressRange range : set.getAddressRanges()) {
				setX.add(range);
			}
			Map<Address, Set<TaintQueryResult>> map = service.getVarnodeMap();
			Map<Address, Set<TaintQueryResult>> mapX = new HashMap<>();
			for (Entry<Address, Set<TaintQueryResult>> entry : map.entrySet()) {
				Set<TaintQueryResult> entryX = new HashSet<>();
				entryX.addAll(entry.getValue());
				mapX.put(entry.getKey(), entryX);
			}
			for (int row : selected) {
				Map<String, Object> r = tableProvider.getRow(row);
				String kind = (String) r.get("kind");
				if (kind.equals("instruction") || kind.startsWith("path ")) {
					removeTaintedInstruction(map, r);
				}
				if (kind.equals("variable")) {
					removeTaintedVariable(map, r);
				}

				Address addr = (Address) r.get("Address");
				if (addr != null) {
					set.delete(addr, addr);
				}
			}

			service.setVarnodeMap(map, false);
			service.setAddressSet(set, false);
		}

	}

	private void removeTaintedVariable(Map<Address, Set<TaintQueryResult>> map,
			Map<String, Object> r) {
		Address faddr = (Address) r.get("entry");
		Set<TaintQueryResult> vset = getSet(map, faddr);
		vset.remove(new TaintQueryResult(r));
	}

	private void removeTaintedInstruction(Map<Address, Set<TaintQueryResult>> map,
			Map<String, Object> r) {
		Address faddr = (Address) r.get("entry");
		String fqname = (String) r.get("location");
		Set<TaintQueryResult> vset = getSet(map, faddr);
		String edgeId = SarifUtils.getEdge(fqname);
		if (edgeId != null) {
			String srcId = SarifUtils.getEdgeSource(edgeId);
			LogicalLocation[] srcNodes = SarifUtils.getNodeLocs(srcId);
			for (LogicalLocation lloc : srcNodes) {
				TaintQueryResult res = new TaintQueryResult(r, run, lloc);
				vset.remove(res);
			}
			String dstId = SarifUtils.getEdgeDest(edgeId);
			LogicalLocation[] dstNodes = SarifUtils.getNodeLocs(dstId);
			for (LogicalLocation lloc : dstNodes) {
				TaintQueryResult res = new TaintQueryResult(r, run, lloc);
				vset.remove(res);
			}
			map.put(faddr, vset);
		}
	}

	private Set<TaintQueryResult> getSet(Map<Address, Set<TaintQueryResult>> map, Address faddr) {
		Set<TaintQueryResult> vset = map.get(faddr);
		if (vset == null) {
			vset = new HashSet<TaintQueryResult>();
			map.put(faddr, vset);
		}
		return vset;
	}

}
