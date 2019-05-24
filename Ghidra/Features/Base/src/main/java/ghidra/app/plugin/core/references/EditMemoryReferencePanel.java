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
package ghidra.app.plugin.core.references;

import java.awt.*;
import java.awt.event.*;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.border.LineBorder;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.table.AbstractTableModel;

import org.jdom.Element;

import docking.widgets.checkbox.GCheckBox;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.label.GDLabel;
import docking.widgets.label.GLabel;
import ghidra.app.util.AddressInput;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.program.util.OperandFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.layout.PairLayout;
import resources.ResourceManager;

class EditMemoryReferencePanel extends EditReferencePanel {

	private static ImageIcon PULLDOWN_ICON = ResourceManager.loadImage("images/menu16.gif");

	private static final RefType[] MEM_REF_TYPES = RefTypeFactory.getMemoryRefTypes();

	private static final int MAX_HISTORY_LENGTH = 10;

	private WeakHashMap<Program, List<Address>> addrHistoryMap = new WeakHashMap<>();

	private ReferencesPlugin plugin;

	// Fields required for ADD
	private CodeUnit fromCodeUnit;
	private int opIndex;

	// Fields required for EDIT
	private Reference editRef;
	private JLabel addrLabel;
	private AddressInput toAddressField;
	private JButton addrHistoryButton;
	private JCheckBox offsetCheckbox;
	private JTextField offsetField;
	private GhidraComboBox<RefType> refTypes;
	private long defaultOffset;
	private JWindow historyWin;
	private HistoryTableModel model;
	private JTable displayTable;

	private boolean isValidState;

	EditMemoryReferencePanel(ReferencesPlugin plugin) {
		super("MEM");
		this.plugin = plugin;
		buildPanel();
	}

	@Override
	public void requestFocus() {
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				// do later to override the default later nature of focus
				toAddressField.requestFocus();
			}
		});
	}

	private void buildPanel() {
		setLayout(new PairLayout(10, 10, 160));

		offsetCheckbox = new GCheckBox("Offset:");
		offsetCheckbox.setHorizontalAlignment(SwingConstants.RIGHT);
		offsetCheckbox.addChangeListener(new ChangeListener() {
			@Override
			public void stateChanged(ChangeEvent e) {
				enableOffsetField(offsetCheckbox.isSelected());
			}
		});
		offsetField = new JTextField();

		addrLabel = new GDLabel("Base Address:");
		addrLabel.setHorizontalAlignment(SwingConstants.RIGHT);
		Dimension d = addrLabel.getPreferredSize();
		addrLabel.setPreferredSize(d);

		toAddressField = new AddressInput();

		addrHistoryButton = new JButton(PULLDOWN_ICON);
		addrHistoryButton.addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent e) {
				if (addrHistoryButton.isEnabled()) {
					toggleAddressHistoryPopup();
				}
			}

			@Override
			public void mouseReleased(MouseEvent e) {
				// TODO Auto-generated method stub
				super.mouseReleased(e);
			}
		});
		addrHistoryButton.setText(null);
		addrHistoryButton.setMargin(new Insets(0, 0, 0, 0));
		addrHistoryButton.setFocusable(false);
		addrHistoryButton.setToolTipText("Address History");

		refTypes = new GhidraComboBox<>(MEM_REF_TYPES);

		JPanel addrPanel = new JPanel(new BorderLayout());
		addrPanel.add(toAddressField, BorderLayout.CENTER);
		addrPanel.add(addrHistoryButton, BorderLayout.EAST);

		add(offsetCheckbox);
		add(offsetField);

		add(addrLabel);
		add(addrPanel);

		add(new GLabel("Ref-Type:", SwingConstants.RIGHT));
		add(refTypes);

		enableOffsetField(false);
	}

	private void enableOffsetField(boolean state) {
		offsetCheckbox.setSelected(state);
		offsetField.setEnabled(state);
		offsetField.setBackground(state ? Color.WHITE : getBackground());
		if (!state) {
			offsetField.setText("0x0");
		}
		else {
			boolean neg = (defaultOffset < 0);
			String offStr =
				(neg ? "-" : "+") + "0x" + Long.toHexString(neg ? -defaultOffset : defaultOffset);
			offsetField.setText(offStr);
			Address addr = toAddressField.getAddress();
			if (addr == null || addr.getOffset() == defaultOffset) {
				addr = getLastHistoryAddress(fromCodeUnit.getProgram());
				if (addr != null) {
					toAddressField.setAddress(addr);
				}
				else {
					toAddressField.clear();
				}
			}
		}
		addrLabel.setText(state ? "Base Address:" : "To Address:");
	}

	private void populateRefTypes(RefType adhocType) {
		refTypes.clearModel();
		for (RefType rt : MEM_REF_TYPES) {
			if (adhocType == rt) {
				adhocType = null;
			}
			refTypes.addItem(rt);
		}
		if (adhocType != null) {
			refTypes.addItem(adhocType);
		}
	}

	@Override
	void initialize(CodeUnit fromCu, Reference editReference) {
		isValidState = false;
		this.fromCodeUnit = fromCu;
		this.editRef = editReference;
		defaultOffset = 0;

		Address toAddr = editReference.getToAddress();
		if (!toAddr.isMemoryAddress()) {
			throw new IllegalArgumentException("Expected memory reference");
		}

		if (editReference.isOffsetReference()) {
			defaultOffset = ((OffsetReference) editReference).getOffset();
			toAddr = toAddr.subtractWrap(defaultOffset);
		}

		toAddressField.setAddressFactory(fromCu.getProgram().getAddressFactory(), false, false);
		toAddressField.setAddress(toAddr);
		enableOffsetField(editReference.isOffsetReference());

		RefType rt = editReference.getReferenceType();
		populateRefTypes(rt);
		refTypes.setSelectedItem(rt);

		addrHistoryButton.setEnabled(getAddressHistorySize(fromCu.getProgram()) != 0);

		validate();
		isValidState = true;
	}

	@Override
	boolean initialize(CodeUnit fromCu, int fromOpIndex, int fromSubIndex) {
		isValidState = false;
		this.editRef = null;
		this.fromCodeUnit = fromCu;
		defaultOffset = 0;

		Program p = fromCu.getProgram();

		addrHistoryButton.setEnabled(getAddressHistorySize(p) != 0);

		toAddressField.setAddressFactory(p.getAddressFactory(), false, false);

		Address cuAddr = fromCu.getMinAddress();

		RefType rt = RefTypeFactory.getDefaultMemoryRefType(fromCu, fromOpIndex, null, false);
		populateRefTypes(rt);
		refTypes.setSelectedItem(rt);

		if (fromSubIndex < 0) {
			Program program = plugin.getCurrentProgram();
			ProgramLocation location = plugin.getCurrentLocation();
			Address toAddr = null;
			if (p == program && location != null) {
				toAddr = getSuggestedLocationAddress(program, location);
			}
			if (toAddr == null || toAddr.equals(cuAddr)) {
				toAddressField.clear();
			}
			else {
				toAddressField.setAddress(toAddr);
			}
			enableOffsetField(false);
			toAddressField.select();
			return setOpIndex(fromOpIndex);
		}

		Address toAddr = null;
		boolean enableOffset = false;

		if (fromCu instanceof Data) {
			Object val = ((Data) fromCu).getValue();
			if (val instanceof Address) {
				toAddr = (Address) val;
			}
			else if (val instanceof Scalar) {
				Scalar s = (Scalar) val;
				defaultOffset = s.getSignedValue();
				toAddr = getDefaultAddress(p.getAddressFactory(), cuAddr, s.getUnsignedValue());
			}
		}
		else if (fromOpIndex >= 0) {
			Scalar s = fromCu.getScalar(fromOpIndex);
			if (s == null) {
				List<?> objs =
					((Instruction) fromCu).getDefaultOperandRepresentationList(fromOpIndex);
				if (objs != null) {
					if (objs.size() > fromSubIndex) {
						Object obj = objs.get(fromSubIndex);
						if (obj instanceof Scalar) {
							s = (Scalar) objs.get(fromSubIndex);
						}
						else if (obj instanceof Address) {
							toAddr = (Address) obj;
						}
					}
					if (s == null && toAddr == null) {
						for (Object obj : objs) {
							if (obj instanceof Scalar) {
								s = (Scalar) obj;
								break;
							}
						}
					}
				}
			}
			if (s != null) {
				defaultOffset = s.getSignedValue();
				toAddr = getDefaultAddress(p.getAddressFactory(), cuAddr, s.getUnsignedValue());
			}
			else if (toAddr == null) {
				toAddr = fromCu.getAddress(fromOpIndex);
			}
			if (toAddr != null) {
				Reference r = p.getReferenceManager().getReference(fromCu.getMinAddress(), toAddr,
					fromOpIndex);
				if (r != null) {
					toAddr = null;
					if (r.isOffsetReference()) {
						OffsetReference offRef = (OffsetReference) r;
						enableOffset = true;
						toAddr = offRef.getBaseAddress();
					}
				}
			}
		}

		if (toAddr != null && !toAddr.equals(cuAddr)) {
			toAddressField.setAddress(toAddr);
			toAddressField.select();
		}
		else {
			toAddressField.clear();
		}

		if (toAddr != null) {
			rt = RefTypeFactory.getDefaultMemoryRefType(fromCu, fromOpIndex, toAddr, false);
			populateRefTypes(rt);
			refTypes.setSelectedItem(rt);
		}

		enableOffsetField(enableOffset);

		return setOpIndex(fromOpIndex);
	}

	private Address getSuggestedLocationAddress(Program program, ProgramLocation loc) {
		Address cuAddr = loc.getAddress();
		if (loc instanceof OperandFieldLocation) {
			CodeUnit cu = program.getListing().getCodeUnitAt(cuAddr);
			if (cu instanceof Data) {
				Data d = (Data) cu;
				if (d.isDefined()) {
					Object obj = d.getValue();
					if (obj instanceof Address) {
						return (Address) obj;
					}
					if (obj instanceof Scalar) {
						Scalar s = (Scalar) obj;
						return getDefaultAddress(program.getAddressFactory(), cuAddr,
							s.getUnsignedValue());
					}
				}
			}
		}
		return cuAddr;
	}

	private Address getDefaultAddress(AddressFactory addrFactory, Address fromAddr, long offset) {

		AddressSpace contextAddrSpace = fromAddr.getAddressSpace();
		long addrOffset = offset * contextAddrSpace.getAddressableUnitSize();

		try {
			return fromAddr.getNewAddress(addrOffset);
		}
		catch (AddressOutOfBoundsException e) {
			// ignore
		}

		AddressSpace defaultSpace = addrFactory.getDefaultAddressSpace();
		addrOffset = offset * defaultSpace.getAddressableUnitSize();

		try {
			return fromAddr.getNewAddress(addrOffset);
		}
		catch (AddressOutOfBoundsException e) {
			// ignore
		}
		return null;
	}

	@Override
	boolean setOpIndex(int opIndex) {

		if (editRef != null) {
			throw new IllegalStateException("setOpIndex only permitted for ADD case");
		}

		//isValidState = false;

		this.opIndex = opIndex;
		isValidState = true;
		return true;
	}

	@Override
	boolean applyReference() {
		if (!isValidState) {
			throw new IllegalStateException();
		}

		boolean isOffsetRef = offsetCheckbox.isSelected();
		long offset = 0;
		if (isOffsetRef) {
			String str = offsetField.getText();
			try {
				offset = parseLongInput(str);
			}
			catch (NumberFormatException e) {
				showInputErr("Valid 'Offset' is required!\nBe sure to prefix hex data with '0x'.");
				return false;
			}
		}

		Address toAddr = toAddressField.getAddress();
		if (toAddr == null) {
			AddressSpace space = toAddressField.getAddressSpace();
			showInputErr("Invalid memory address offset specified; " + space.getName() +
				" offset must be in range: " + space.getMinAddress().toString(false) + " to " +
				space.getMaxAddress().toString(false));
			return false;
		}

		// Don't try to process an address that is not valid. 
		if (!toAddr.isMemoryAddress()) {
			showInputErr("Invalid memory address specified");
			return false;
		}

		addHistoryAddress(fromCodeUnit.getProgram(), toAddr);

		toAddr = plugin.checkMemoryAddress(this, fromCodeUnit.getProgram(), toAddr, offset);
		if (toAddr == null) {
			return false;
		}
		toAddr = toAddr.addWrap(offset);

		RefType refType = (RefType) refTypes.getSelectedItem();
		if (refType == null) {
			showInputErr("A 'Ref-Type' must be selected.");
			return false;
		}

		if (editRef != null) {
			return plugin.updateReference(editRef, fromCodeUnit, toAddr, isOffsetRef, offset,
				refType);
		}
		return plugin.addReference(fromCodeUnit, opIndex, toAddr, isOffsetRef, offset, refType);
	}

	private int getAddressHistorySize(Program program) {
		List<Address> list = addrHistoryMap.get(program);
		return list != null ? list.size() : 0;
	}

	private Address getLastHistoryAddress(Program program) {
		List<Address> list = addrHistoryMap.get(program);
		return list != null ? list.get(0) : null;
	}

	private void addHistoryAddress(Program program, Address addr) {
		List<Address> list = addrHistoryMap.get(program);
		if (list == null) {
			list = new ArrayList<>();
			addrHistoryMap.put(program, list);
		}
		list.remove(addr);
		list.add(0, addr);
		if (list.size() > MAX_HISTORY_LENGTH) {
			list.remove(MAX_HISTORY_LENGTH);
		}
	}

	private void hideAddressHistoryPopup() {
		if (historyWin != null) {
			historyWin.setVisible(false);
			historyWin.dispose();
			historyWin = null;
			model = null;
			displayTable = null;
		}
	}

	private class HistoryTableModel extends AbstractTableModel {
		private SymbolTable symTable;
		private List<Address> addrList;

		HistoryTableModel(Program program) {
			this.symTable = program.getSymbolTable();
			this.addrList = addrHistoryMap.get(fromCodeUnit.getProgram());
		}

		@Override
		public int getColumnCount() {
			return 2;
		}

		@Override
		public int getRowCount() {
			return addrList != null ? addrList.size() : 0;
		}

		public Address getAddress(int rowIndex) {
			return addrList != null ? addrList.get(rowIndex) : null;
		}

		@Override
		public Object getValueAt(int rowIndex, int columnIndex) {
			if (addrList == null) {
				return null;
			}
			Address addr = addrList.get(rowIndex);
			if (columnIndex == 0) {
				return addr.toString();
			}
			Symbol s = symTable.getPrimarySymbol(addr);
			if (s != null) {
				return s.getName();
			}
			return null;
		}
	}

	private void toggleAddressHistoryPopup() {

		if (historyWin != null) {
			hideAddressHistoryPopup();
			return;
		}

		List<Address> list = addrHistoryMap.get(fromCodeUnit.getProgram());
		Address[] addrs = new Address[list.size()];
		list.toArray(addrs);

		JPanel panel = new JPanel(new BorderLayout(0, 0));

		model = new HistoryTableModel(fromCodeUnit.getProgram());
		displayTable = new JTable(model);
		displayTable.setTableHeader(null);
		displayTable.setBorder(new LineBorder(Color.BLACK));
		displayTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

		displayTable.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				int row = displayTable.getSelectedRow();
				Address addr = model.getAddress(row);
				toAddressField.setAddress(addr);
				toggleAddressHistoryPopup();
			}

			@Override
			public void mousePressed(MouseEvent e) {
				// Ignore
			}
		});
		displayTable.addMouseMotionListener(new MouseMotionAdapter() {
			@Override
			public void mouseMoved(MouseEvent e) {
				if (e.getSource() == displayTable) {
					Point location = e.getPoint();
					Rectangle r = new Rectangle();
					displayTable.computeVisibleRect(r);
					if (r.contains(location)) {
						updateTableSelectionForEvent(e);
					}
				}
			}
		});

		panel.add(displayTable, BorderLayout.CENTER);

		int w = toAddressField.getWidth() + addrHistoryButton.getWidth();
		Dimension d = displayTable.getPreferredSize();
		displayTable.setPreferredSize(new Dimension(w, d.height));

		Window dlgWin = findMyWindow();
		historyWin = new JWindow(dlgWin);
		historyWin.getContentPane().setLayout(new BorderLayout(0, 0));
		historyWin.getContentPane().add(panel, BorderLayout.CENTER);
		historyWin.pack();

		Point p = new Point();
		SwingUtilities.convertPointToScreen(p, toAddressField);
		p.y += toAddressField.getHeight();
		historyWin.setLocation(p);

		KeyboardFocusManager.getCurrentKeyboardFocusManager().addPropertyChangeListener(
			"focusOwner", new PropertyChangeListener() {
				boolean hasFocus = false;

				@Override
				public void propertyChange(PropertyChangeEvent evt) {
					Object focusOwner = evt.getNewValue();
					if (focusOwner == displayTable || focusOwner == historyWin) {
						hasFocus = true;
					}
					else if (hasFocus) {
						hasFocus = false;
						KeyboardFocusManager.getCurrentKeyboardFocusManager().removePropertyChangeListener(
							"focusOwner", this);
						hideAddressHistoryPopup();
					}
				}
			});

		historyWin.setVisible(true);

		dlgWin.addComponentListener(new ComponentListener() {
			@Override
			public void componentHidden(ComponentEvent e) {
				hideAddressHistoryPopup();
			}

			@Override
			public void componentMoved(ComponentEvent e) {
				hideAddressHistoryPopup();
			}

			@Override
			public void componentResized(ComponentEvent e) {
				hideAddressHistoryPopup();
			}

			@Override
			public void componentShown(ComponentEvent e) {
			}
		});

		//displayList.requestFocus();

//		historyWin.addFocusListener(new FocusListener() {
//			public void focusGained(FocusEvent e) {
//			}
//			public void focusLost(FocusEvent e) {
//				toggleAddressHistoryPopup();
//			}
//		});

	}

	private void updateTableSelectionForEvent(MouseEvent anEvent) {
		Point location = anEvent.getPoint();
		if (displayTable == null) {
			return;
		}
		int index = displayTable.rowAtPoint(location);
		if (index == -1) {
			if (location.y < 0) {
				index = 0;
			}
			else {
				index = model.getRowCount() - 1;
			}
		}
		if (displayTable.getSelectedRow() != index) {
			displayTable.getSelectionModel().setSelectionInterval(index, index);
		}
	}

	private Window findMyWindow() {
		Component c = getParent();
		while (c != null && !(c instanceof Window)) {
			c = c.getParent();
		}
		return (Window) c;
	}

	@Override
	void cleanup() {
		isValidState = false;
		fromCodeUnit = null;
		editRef = null;
	}

	@Override
	boolean isValidContext() {
		return isValidState;
	}

	@SuppressWarnings("unchecked")
	void readXmlDataState(Element element) {
		List<Element> programElements = element.getChildren("ADDR_HISTORY");
		Iterator<Element> iter = programElements.iterator();
		while (iter.hasNext()) {
			Element programElement = iter.next();
			String programName = programElement.getAttributeValue("PROGRAM");
			Program program = getOpenProgram(programName);
			if (program != null) {
				AddressFactory addrFactory = program.getAddressFactory();
				List<Element> addrElements = programElement.getChildren("ADDRESS");
				Iterator<Element> addrIter = addrElements.iterator();
				while (addrIter.hasNext()) {
					Element addrElement = addrIter.next();
					String addrStr = addrElement.getAttributeValue("VALUE");
					if (addrStr != null) {
						Address addr = addrFactory.getAddress(addrStr);
						if (addr != null) {
							addHistoryAddress(program, addr);
						}
					}
				}
			}
		}
	}

	void writeXmlDataState(Element element) {
		for (Program program : addrHistoryMap.keySet()) {
			Element programElement = new Element("ADDR_HISTORY");
			programElement.setAttribute("PROGRAM", program.getDomainFile().toString());
			List<Address> addressList = addrHistoryMap.get(program);
			for (Address address : addressList) {
				Element addrElement = new Element("ADDRESS");
				addrElement.setAttribute("VALUE", address.toString());
				programElement.addContent(addrElement);
			}
			element.addContent(programElement);
		}
	}

	private Program getOpenProgram(String name) {
		Program[] openPrograms = plugin.getProgramManager().getAllOpenPrograms();
		for (Program program : openPrograms) {
			if (name.equals(program.getDomainFile().toString())) {
				return program;
			}
		}
		return null;
	}

}
