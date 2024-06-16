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
package ghidra.features.bsim.gui.search.results;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.util.List;

import javax.swing.JPanel;

import docking.DialogComponentProvider;
import docking.widgets.table.GTableFilterPanel;
import ghidra.features.bsim.gui.search.results.apply.AbstractBSimApplyTask;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.Program;
import ghidra.util.table.GhidraFilterTable;
import ghidra.util.table.GhidraTable;

/**
 * Panel that displays the results of executing an "apply-rename" operation on a set of BSim 
 * query results. The results are presented in a {@link GhidraTable}; see the 
 * {@link BSimApplyResultsTableModel} for details on its structure.
 * <p>
 * Filtering is provided on the results using a standard {@link GTableFilterPanel}.
 * 
 * @see BSimApplyResultsTableModel
 * @see AbstractBSimApplyTask
 *
 */
public class BSimApplyResultsDisplayDialog extends DialogComponentProvider {

	private ServiceProvider serviceProvider;
	private Program program;
	private GhidraFilterTable<BSimApplyResult> table;

	public BSimApplyResultsDisplayDialog(ServiceProvider serviceProvider,
		List<BSimApplyResult> results, Program program) {
		super(createTitle(results));
		setRememberSize(false);

		this.serviceProvider = serviceProvider;
		this.program = program;

		addWorkPanel(createWorkPanel(results));
		addOKButton();

	}

	private static String createTitle(List<BSimApplyResult> results) {
		StringBuilder builder = new StringBuilder();
		int successes = 0;
		int errors = 0;
		int ignored = 0;
		for (BSimApplyResult result : results) {
			if (result.isError()) {
				errors++;
			}
			else if (result.isIgnored()) {
				ignored++;
			}
			else {
				successes++;
			}
		}

		builder.append("BSim Apply Results (");
		builder.append(successes);
		builder.append(" successfully applied");
		if (errors > 0) {
			builder.append(", ");
			builder.append(errors);
			builder.append(" error(s)");
		}
		if (ignored > 0) {
			builder.append(", ");
			builder.append(ignored);
			builder.append(" ignored");
		}
		builder.append(")");
		return builder.toString();
	}

	@Override
	protected void okCallback() {
		close();
	}

	@Override
	public boolean isModal() {
		return false;
	}

	private JPanel createWorkPanel(List<BSimApplyResult> results) {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setPreferredSize(new Dimension(1200, 400));
		BSimApplyResultsTableModel model =
			new BSimApplyResultsTableModel("results model", serviceProvider, program, null,
				results);

		table = new GhidraFilterTable<>(model);
		table.installNavigation(serviceProvider);

		panel.add(table, BorderLayout.CENTER);

		return panel;
	}
}
