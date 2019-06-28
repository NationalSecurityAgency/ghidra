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
package ghidra.app.plugin.core.compositeeditor;

import java.awt.BorderLayout;

import javax.swing.*;
import javax.swing.border.EmptyBorder;

import ghidra.program.model.data.*;
import ghidra.util.layout.*;

/**
 * <code>BitFieldViewerPanel</code> provides the ability to examine bitfield placement
 * within structures.
 * TODO: consider using as a hover panel
 */
public class BitFieldViewerPanel extends JPanel {

	private Composite composite;
	private DataTypeComponent bitfieldDtc;

	private JLabel allocationOffsetLabel;

	private BitFieldPlacementComponent placementComponent;

	BitFieldViewerPanel(DataTypeComponent bitfieldDtc, int allocationOffset) {
		super();
		this.bitfieldDtc = bitfieldDtc;
		this.composite = (Composite) bitfieldDtc.getParent();

		setLayout(new VerticalLayout(5));
		setFocusTraversalKeysEnabled(true);

		setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

		if (composite instanceof Structure) {
			add(createAllocationOffsetPanel());
		}
		add(createPlacementPanel());
		add(createLegendPanel());
		initView(allocationOffset);
	}

	private JPanel createLegendPanel() {
		JPanel legendPanel = new JPanel(new BorderLayout());
		legendPanel.add(new BitFieldPlacementComponent.BitFieldLegend(bitfieldDtc),
			BorderLayout.WEST);
		return legendPanel;
	}

	private JPanel createAllocationOffsetPanel() {

		JPanel panel = new JPanel(new HorizontalLayout(5));

		allocationOffsetLabel = new JLabel();
		allocationOffsetLabel.setHorizontalTextPosition(SwingConstants.LEFT);
		panel.add(allocationOffsetLabel);

		return panel;
	}

	private void updateAllocationOffsetLabel() {
		if (composite instanceof Structure) {
			String text =
				"Structure Offset of Allocation Unit: " + placementComponent.getAllocationOffset();
			allocationOffsetLabel.setText(text);
		}
	}

	private JPanel createPlacementPanel() {
		JPanel midPanel = new JPanel(new PairLayout(5, 5));

		JPanel leftMidPanel = new JPanel(new VerticalLayout(13));
		leftMidPanel.setBorder(BorderFactory.createEmptyBorder(12, 8, 12, 0));
		JLabel byteOffsetLabel = new JLabel("Byte Offset:", SwingConstants.RIGHT);
		byteOffsetLabel.setToolTipText("Byte Offset is relative to start of allocation unit");
		leftMidPanel.add(byteOffsetLabel);
		leftMidPanel.add(new JLabel("Bits:", SwingConstants.RIGHT));
		midPanel.add(leftMidPanel);

		placementComponent = new BitFieldPlacementComponent(composite);
		placementComponent.setFont(UIManager.getFont("TextField.font"));

		JPanel p = new JPanel(new BorderLayout());
		p.add(placementComponent, BorderLayout.WEST);
		p.setBorder(new EmptyBorder(0, 0, 5, 0));

		JScrollPane scrollPane = new JScrollPane(p, ScrollPaneConstants.VERTICAL_SCROLLBAR_NEVER,
			ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		scrollPane.getViewport().setBackground(getBackground());
		scrollPane.setBorder(null);

		midPanel.add(scrollPane);
		return midPanel;
	}

	/**
	 * Initialize for edit of existing component or no component if bitfieldDtc is null.
	 * If null an allocation size of 4-bytes will be used but may be adjusted.
	 * @param allocationOffset allocation offset to be used
	 * @param useExistingAllocationSize if true attempt to use existing allocation size
	 */
	private void initView(int allocationOffset) {
		DataType initialBaseDataType = null;
		int allocationSize = -1;
		if (bitfieldDtc != null) {
			if (!bitfieldDtc.isBitFieldComponent()) {
				throw new IllegalArgumentException("unsupport data type component");
			}
			BitFieldDataType bitfieldDt = (BitFieldDataType) bitfieldDtc.getDataType();
			initialBaseDataType = bitfieldDt.getBaseDataType();
			if (allocationSize < 1) {
				allocationSize = initialBaseDataType.getLength();
			}
			int allocationAdjust = composite.getLength() - allocationOffset - allocationSize;
			if (allocationAdjust < 0) {
				allocationSize += allocationAdjust;
			}
		}
		if (allocationSize < 1) {
			allocationSize = 4;
		}

		placementComponent.updateAllocation(allocationSize, allocationOffset);
		placementComponent.init(bitfieldDtc);
		updateAllocationOffsetLabel();
	}

}
