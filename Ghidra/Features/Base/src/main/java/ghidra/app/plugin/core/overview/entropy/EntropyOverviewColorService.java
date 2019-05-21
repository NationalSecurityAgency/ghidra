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
package ghidra.app.plugin.core.overview.entropy;

import java.awt.Color;
import java.text.DecimalFormat;
import java.util.*;

import docking.ActionContext;
import docking.DialogComponentProvider;
import docking.action.DockingActionIf;
import ghidra.app.plugin.core.overview.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.HTMLUtilities;
import ghidra.util.HelpLocation;

/**
 * Service for associating colors with a programs address's based on an Entropy computation for
 * the bytes in a chunk around the given address.
 */
public class EntropyOverviewColorService implements OverviewColorService {
	private static DecimalFormat formatter = new DecimalFormat("#0.0");
	private Program program;
	private int chunkSize;
	private byte[] chunkBuffer;
	private double[] logtable;
	private int[] histogram = new int[256];
	private Palette palette;
	private EntropyOverviewOptionsManager entropyOptionsManager;
	private OverviewColorComponent overviewComponent;
	private OverviewColorLegendDialog legendDialog;

	@Override
	public String getName() {
		return "Entropy";
	}

	@Override
	public Color getColor(Address address) {
		if (program == null) {
			return palette.getColor(0);
		}
		int entropy = computeEntropy(address);
		return palette.getColor(entropy);
	}

	@Override
	public HelpLocation getHelpLocation() {
		return new HelpLocation(OverviewColorPlugin.HELP_TOPIC, "EntropyOverviewBar");
	}

	@Override
	public void initialize(PluginTool tool) {
		entropyOptionsManager = new EntropyOverviewOptionsManager(tool, this);
		chunkSize = entropyOptionsManager.getChunkSize();
		chunkBuffer = new byte[chunkSize];
		palette = entropyOptionsManager.getPalette();
	}

	@Override
	public void setOverviewComponent(OverviewColorComponent component) {
		this.overviewComponent = component;
	}

	@Override
	public String getToolTipText(Address address) {
		if (address == null) {
			return null;
		}
		int entropyScaled = computeEntropy(address);
		double entropy = (entropyScaled * 8.0d) / 255; 	// convert back from palette scale to original entropy value
		StringBuilder buffer = new StringBuilder();
		buffer.append("<b>");
		buffer.append(HTMLUtilities.escapeHTML(getName()));
		buffer.append("</b>\n");
		buffer.append(" ");
		buffer.append(formatter.format(entropy));
		buffer.append(" ");
		buffer.append(HTMLUtilities.escapeHTML(getKnotName(entropyScaled)));
		buffer.append(" ");
		buffer.append(" &nbsp&nbsp&nbsp(");
		buffer.append(HTMLUtilities.escapeHTML(getBlockName(address)));
		buffer.append(" ");
		buffer.append(HTMLUtilities.escapeHTML(address.toString()));
		buffer.append(" )");
		return HTMLUtilities.toWrappedHTML(buffer.toString(), 0);
	}

	private String getKnotName(int entropy) {
		ArrayList<KnotRecord> knots = palette.getKnots();
		for (KnotRecord knotRecord : knots) {
			if (knotRecord.contains(entropy)) {
				return knotRecord.getName();
			}
		}
		return "";
	}

	private String getBlockName(Address address) {
		MemoryBlock block = program.getMemory().getBlock(address);
		if (block != null) {
			return block.getName();
		}
		return "";
	}

	private int computeEntropy(Address address) {
		if (address == null) {
			return 0;
		}
		MemoryBlock block = program.getMemory().getBlock(address);
		if (block == null) {
			return 0;
		}
		Address chunkStartAddress = getChunkStartAddress(block, address);
		try {
			int bytesRead = block.getBytes(chunkStartAddress, chunkBuffer);
			computeHistogram(bytesRead);
			return quantizeChunk();
		}
		catch (MemoryAccessException e) {
			return 0;  // no bytes, no entropy
		}
	}

	private int quantizeChunk() {
		if (logtable == null) {
			buildLogTable();
		}
		double sum = 0.0;
		for (int i = 0; i < 256; ++i) {
			sum += logtable[histogram[i]];
		}
		sum = (sum / 8.0) * 256.0;
		int val = (int) Math.floor(sum);
		if (val > 255) {
			val = 255;
		}
		return val;
	}

	private void computeHistogram(int byteCount) {
		Arrays.fill(histogram, 0);
		for (int i = 0; i < byteCount; ++i) {
			histogram[128 + chunkBuffer[i]] += 1;
		}
	}

	private Address getChunkStartAddress(MemoryBlock block, Address address) {
		long offset = address.subtract(block.getStart());
		long chunk = offset / chunkSize;
		return block.getStart().add(chunk * chunkSize);
	}

	@Override
	public void setProgram(Program program) {
		this.program = program;
	}

	private void buildLogTable() {
		logtable = new double[chunkSize + 1];
		double logtwo = Math.log(2.0);
		double chunkfloat = chunkSize;
		for (int i = 1; i < chunkSize; ++i) {
			double prob = i / chunkfloat;
			logtable[i] = -prob * (Math.log(prob) / logtwo);
		}
		logtable[0] = 0.0;
		logtable[chunkSize] = 0.0;
	}

	/**
	 * Kick when the colors have been changed.
	 */
	public void paletteChanged() {
		if (overviewComponent != null) {
			overviewComponent.refreshAll();
		}
		if (legendDialog != null) {
			legendDialog.refresh();
		}
	}

	@Override
	public List<DockingActionIf> getActions() {
		List<DockingActionIf> actions = new ArrayList<>();
		actions.add(new AbstractColorOverviewAction("Show Legend", getName(), overviewComponent,
			getHelpLocation()) {

			@Override
			public void actionPerformed(ActionContext context) {
				PluginTool tool = overviewComponent.getTool();
				tool.showDialog(getLegendDialog());
			}
		});
		return actions;
	}

	@Override
	public Program getProgram() {
		return program;
	}

	private DialogComponentProvider getLegendDialog() {
		if (legendDialog == null) {
			LegendPanel legendPanel = new LegendPanel();
			legendPanel.setPalette(palette);
			legendDialog =
				new OverviewColorLegendDialog("Entropy Legend", legendPanel, getHelpLocation());
		}
		return legendDialog;
	}
}
