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
package sarif;

import java.awt.Color;
import java.awt.image.BufferedImage;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.contrastsecurity.sarif.Location;
import com.contrastsecurity.sarif.LogicalLocation;
import com.contrastsecurity.sarif.Result;
import com.contrastsecurity.sarif.SarifSchema210;

import docking.widgets.table.ObjectSelectedListener;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.service.graph.AttributedGraph;
import ghidra.service.graph.EmptyGraphType;
import ghidra.service.graph.GraphDisplay;
import ghidra.service.graph.GraphDisplayOptions;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.GraphException;
import resources.ResourceManager;
import sarif.handlers.SarifResultHandler;
import sarif.handlers.SarifRunHandler;
import sarif.managers.ProgramSarifMgr;
import sarif.model.SarifDataFrame;
import sarif.view.ImageArtifactDisplay;
import sarif.view.SarifResultsTableProvider;

/**
 * Controller for handling interactions between the SARIF log file and Ghidra
 */
public class SarifController implements ObjectSelectedListener<Map<String, Object>> {

	private SarifPlugin plugin;
	private Program program;

	private ColorizingService coloringService;
	private BookmarkManager bookmarkManager;
	private ProgramSarifMgr programManager;

	private Set<SarifResultsTableProvider> providers = new HashSet<>();
	public Set<ImageArtifactDisplay> artifacts = new HashSet<>();
	public Set<GraphDisplay> graphs = new HashSet<>();

	public Set<SarifResultHandler> getSarifResultHandlers() {
		Set<SarifResultHandler> set = new HashSet<>();
		set.addAll(ClassSearcher.getInstances(SarifResultHandler.class));
		return set;
	}

	public Set<SarifRunHandler> getSarifRunHandlers() {
		Set<SarifRunHandler> set = new HashSet<>();
		set.addAll(ClassSearcher.getInstances(SarifRunHandler.class));
		return set;
	}

	public SarifController(Program program, SarifPlugin plugin) {
		this.program = program;
		this.plugin = plugin;
		this.coloringService = plugin.getTool().getService(ColorizingService.class);
		this.programManager = new ProgramSarifMgr(program);
	}

	public SarifController(ProgramSarifMgr manager) {
		this.program = null;
		this.plugin = null;
		this.coloringService = null; // plugin.getTool().getService(ColorizingService.class);
		this.programManager = manager;
	}

	public void dispose() {
		Set<SarifResultsTableProvider> copyProviders = new HashSet<>();
		copyProviders.addAll(providers);
		for (SarifResultsTableProvider p : copyProviders) {
			p.dispose();
		}
		Set<ImageArtifactDisplay> copyArtifacts = new HashSet<>();
		copyArtifacts.addAll(artifacts);
		for (ImageArtifactDisplay a : copyArtifacts) {
			a.dispose();
		}
		for (GraphDisplay g : graphs) {
			g.close();
		}
	}

	public void showTable(boolean makeVisible) {
		for (SarifResultsTableProvider p : providers) {
			p.setVisible(makeVisible);
		}
	}

	public void showTable(String logName, SarifSchema210 sarif) {
		SarifDataFrame df = new SarifDataFrame(sarif, this, false);
		SarifResultsTableProvider provider = new SarifResultsTableProvider(logName, this.plugin, this, df);
		provider.filterTable.addSelectionListener(this);
		provider.addToTool();
		provider.setVisible(true);
		provider.setTitle(logName);
		if (!providers.contains(provider)) {
			providers.add(provider);
		}
	}

	public void showImage(String key, BufferedImage img) {
		if (plugin.displayArtifacts()) {
			ImageArtifactDisplay display = new ImageArtifactDisplay(plugin.getTool(), key, "Sarif Parse", img);
			display.setVisible(true);
			artifacts.add(display);
		}
	}

	public void showGraph(AttributedGraph graph) {
		try {
			GraphDisplayBroker service = this.plugin.getTool().getService(GraphDisplayBroker.class);
			boolean append = plugin.appendToGraph();
			GraphDisplay display = service.getDefaultGraphDisplay(append, null);
			GraphDisplayOptions graphOptions = new GraphDisplayOptions(new EmptyGraphType());
			graphOptions.setMaxNodeCount(plugin.getGraphSize());

			if (plugin.displayGraphs()) {
				display.setGraph(graph, graphOptions, graph.getDescription(), append, null);
				graphs.add(display);
			}
		} catch (GraphException | CancelledException e) {
			Msg.error(this, "showGraph failed " + e.getMessage());
		}
	}

	/**
	 * If a results has "listing/<something>" in a SARIF result, this handles
	 * defining our custom API for those
	 *
	 * @param log
	 * @param result
	 * @param key
	 * @param value
	 */
	public void handleListingAction(Result result, String key, Object value) {
		List<Address> addrs = getListingAddresses(result);
		for (Address addr : addrs) {
			switch (key) {
			case "comment":
				/* @formatter:off
				 *  docs/GhidraAPI_javadoc/api/constant-values.html#ghidra.program.model.listing.CodeUnit
				 *  EOL_COMMENT 0
				 *  PRE_COMMENT 1
				 *  POST_COMMENT 2
				 *  PLATE_COMMENT 3
				 *  REPEATABLE_COMMENT 4
				 * @formatter:on
				 */
				String comment = (String) value;
				getProgram().getListing().setComment(addr, CodeUnit.PLATE_COMMENT, comment);
				break;
			case "highlight":
				Color color = Color.decode((String) value);
				coloringService.setBackgroundColor(addr, addr, color);
				break;
			case "bookmark":
				String bookmark = (String) value;
				getProgram().getBookmarkManager().setBookmark(addr, "Sarif", result.getRuleId(), bookmark);
				break;
			}
		}
	}

	public void colorBackground(AddressSetView set, Color color) {
		coloringService.setBackgroundColor(set, color);
	}

	public void colorBackground(Address addr, Color color) {
		coloringService.setBackgroundColor(addr, addr, color);
	}

	public Address longToAddress(Object lval) {
		if (lval instanceof Long) {
			return getProgram().getAddressFactory().getDefaultAddressSpace().getAddress((Long) lval);
		}
		return getProgram().getAddressFactory().getDefaultAddressSpace().getAddress((Integer) lval);
	}

	/**
	 * Get listing addresses associated with a result
	 *
	 * @param result
	 * @return
	 */
	public List<Address> getListingAddresses(Result result) {
		List<Address> addrs = new ArrayList<>();
		if (result.getLocations() != null && result.getLocations().size() > 0) {
			List<Location> locations = result.getLocations();
			for (Location loc : locations) {
				Address addr = locationToAddress(loc);
				if (addr != null) {
					addrs.add(addr);
				}
			}
		}
		return addrs;
	}

	public Address locationToAddress(Location loc) {
		if (loc.getPhysicalLocation() != null) {
			return longToAddress(loc.getPhysicalLocation().getAddress().getAbsoluteAddress());
		}
		if (loc.getLogicalLocations() != null) {
			Set<LogicalLocation> logicalLocations = loc.getLogicalLocations();
			for (LogicalLocation logLoc : logicalLocations) {
				switch (logLoc.getKind()) {
				case "function":
					String fname = logLoc.getName();
					for (Function func : getProgram().getFunctionManager().getFunctions(true)) {
						if (fname.equals(func.getName())) {
							return func.getEntryPoint();
						}
					}
					break;
				default:
					Msg.error(this, "Unknown logical location to handle: " + logLoc.toString());
				}
			}
		}
		return null;
	}

	@SuppressWarnings("unchecked")
	@Override
	public void objectSelected(Map<String, Object> row) {
		if (row != null) {
			if (row.containsKey("CodeFlows")) {
				for (List<Address> flow : (List<List<Address>>) row.get("CodeFlows")) {
					this.plugin.makeSelection(flow);
				}
			}
			if (row.containsKey("Graphs")) {
				for (AttributedGraph graph : (List<AttributedGraph>) row.get("Graphs")) {
					this.showGraph(graph);
				}
			}
		}
	}

	public void removeProvider(SarifResultsTableProvider provider) {
		providers.remove(provider);
	}

	public ProgramSarifMgr getProgramSarifMgr() {
		return programManager;
	}

	public Program getProgram() {
		return program;
	}

	public void setProgram(Program program) {
		this.program = program;
		this.bookmarkManager = program.getBookmarkManager();
		bookmarkManager.defineType("Sarif", ResourceManager.loadImage("images/peach_16.png"), Color.pink, 0);
	}

}
