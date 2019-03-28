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
package ghidra.app.util.exporter;

import java.awt.BorderLayout;
import java.awt.Component;
import java.io.*;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

import docking.widgets.textfield.HintTextField;
import ghidra.app.util.*;
import ghidra.app.util.opinion.IntelHexRecord;
import ghidra.app.util.opinion.IntelHexRecordWriter;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.util.HelpLocation;
import ghidra.util.task.TaskMonitor;

/**
 * Exports the current program (or program selection) as bytes in Intel Hex format. 
 * <p>
 * The output defaults to lines of 16-bytes but this is configurable using the
 * {@link #recordSizeOption} attribute. This allows users to select any record size
 * up to the max of 0xFF. Users may also choose to <code>Drop Extra Bytes</code>, which will
 * cause only lines that match the max record size to be printed; any other 
 * bytes will be dropped. If this option is not set, every byte will be represented in the output.
 */
public class IntelHexExporter extends Exporter {

	/** Option allowing the user to select the address space */
	protected Option addressSpaceOption;
	
	/** Option allowing the user to select the number of bytes in each line of output */
	protected RecordSizeOption recordSizeOption;

	/**
	 * Constructs a new Intel Hex exporter.
	 */
	public IntelHexExporter() {
		this("Intel Hex", "hex", new HelpLocation("ExporterPlugin", "intel_hex"));
	}

	/**
	 * Constructor
	 * 
	 * @param name the name of the exporter
	 * @param extension the extension to use for the output file
	 * @param help location of Ghidra help
	 */
	protected IntelHexExporter(String name, String extension, HelpLocation help) {
		super(name, extension, help);
	}

	@Override
	public List<Option> getOptions(DomainObjectService domainObjectService) {
		List<Option> optionsList = new ArrayList<>();

		DomainObject domainObject = domainObjectService.getDomainObject();
		if (!(domainObject instanceof Program)) {
			return null;
		}
		Program program = (Program) domainObject;

		addressSpaceOption =
			new Option("Address Space", program.getAddressFactory().getDefaultAddressSpace());

		recordSizeOption = new RecordSizeOption("Record Size", Integer.class);

		optionsList.add(addressSpaceOption);
		optionsList.add(recordSizeOption);

		return optionsList;
	}

	@Override
	public void setOptions(List<Option> options) throws OptionException {
		if (!options.isEmpty()) {
			addressSpaceOption = options.get(0);
			recordSizeOption = (RecordSizeOption) options.get(1); 
		}
	}

	/**
	 * Option for exporting Intel Hex records that allows users to specify a record size for the
	 * output. Users may also optionally select the <code>Drop Extra Bytes</code> option that 
	 * will cause only those records that match the maximum size to be output to the file.
	 * 
	 * @see RecordSizeComponent
	 */
	private class RecordSizeOption extends Option {

		// Initialize the record size to 16 bytes when showing the option.
		private final RecordSizeComponent comp = new RecordSizeComponent(16);

		public RecordSizeOption(String name, Class<?> valueClass) {
			super(name, valueClass);
		}

		public RecordSizeOption(String name, Class<?> valueClass, Object value, String arg,
				String group) {
			super(name, valueClass, value, arg, group);
		}

		@Override
		public Component getCustomEditorComponent() {
			return comp;
		}

		@Override
		public Option copy() {
			return new RecordSizeOption(getName(), getValueClass(), getValue(), getArg(),
				getGroup());
		}

		@Override
		public Object getValue() {
			return comp.getValue();
		}

		@Override
		public Class<?> getValueClass() {
			return Integer.class;
		}

		public boolean dropExtraBytes() {
			return comp.dropExtraBytes();
		}
	}

	/**
	 * Component that displays two widgets for setting export options: 
	 * 
	 * <ul>
	 * <li><code>input</code>: a {@link HintTextField} for entering numeric digits; these 
	 * represent the record size for each line of output</li>
	 * <li>dropCb: a {@link JCheckBox} for specifying a setting that enforces that every line in 
	 * the output matches the specified record size</li>
	 * </ul>
	 * 
	 * Note: If the <code>Drop Extra Bytes</code> option is set, any bytes that are left over 
	 * after outputting all lines that match the record size will be omitted from the output.
	 */
	private class RecordSizeComponent extends JPanel {

		private HintTextField input;
		private JCheckBox dropCb;

		public RecordSizeComponent(int recordSize) {
			setLayout(new BorderLayout());
			
			input = new HintTextField(String.valueOf(recordSize), false, new BoundedIntegerVerifier());
			dropCb = new JCheckBox("Drop Extra Bytes");
			
			input.setText(String.valueOf(recordSize));
			
			add(input, BorderLayout.CENTER);
			add(dropCb, BorderLayout.EAST);
		}

		public int getValue() {
			String val = input.getText();
			if (!input.isFieldValid()) {
				return 0x10;
			}

			return Integer.valueOf(val);
		}

		public boolean dropExtraBytes() {
			return dropCb.isSelected();
		}
	}

	/**
	 * Verifier for a {@link HintTextField} that ensures input is a numeric value between
	 * 0 and 0xFF.
	 * <p>
	 * Input may be specified in either decimal or hex.
	 */
	private class BoundedIntegerVerifier extends InputVerifier {

		@Override
		public boolean verify(JComponent input) {
			HintTextField field = (HintTextField) input;
			String text = field.getText();

			// Strip off any leading "0x" chars if the user has put them there - the
			// parseInt method can't handle them.
			if (text.startsWith("0x")) {
				text = text.substring(2);
			}

			// Now try and parse the input; first as hex, then as decimal. 
			Integer val;
			try {
				val = Integer.parseInt(text, 16);
			}
			catch (NumberFormatException e) {
				try {
					val = Integer.parseInt(text);
				}
				catch (NumberFormatException e1) {
					return false;
				}
			}

			return val <= 0xFF && val >= 0;
		}
	}

	@Override
	public boolean export(File file, DomainObject domainObj, AddressSetView addrSet,
			TaskMonitor monitor) throws IOException, ExporterException {

		log.clear();

		if (!(domainObj instanceof Program)) {
			log.appendMsg("Unsupported type: " + domainObj.getClass().getName());
			return false;
		}
		Program program = (Program) domainObj;
		if (program.getMaxAddress().getSize() > 32) {
			log.appendMsg("Cannot be used for programs larger than 32 bits");
			return false;
		}

		if (addressSpaceOption == null || recordSizeOption == null) {
			getOptions(() -> program);
		}

		try (PrintWriter writer = new PrintWriter(new FileOutputStream(file))) {

			Memory memory = program.getMemory();

			if (addrSet == null) {
				addrSet = memory;
			}

			try {
				List<IntelHexRecord> records = dumpMemory(program, memory, addrSet, monitor);
				for (IntelHexRecord record : records) {
					writer.println(record.format());
				}
			}
			catch (MemoryAccessException e) {
				throw new ExporterException(e);
			}
			finally {
				addressSpaceOption = null;
				recordSizeOption = null;
			}
		}

		return true;
	}

	protected List<IntelHexRecord> dumpMemory(Program program, Memory memory,
			AddressSetView addrSetView, TaskMonitor monitor) throws MemoryAccessException {

		int size = (int) recordSizeOption.getValue();
		boolean dropBytes = recordSizeOption.dropExtraBytes();

		IntelHexRecordWriter writer = new IntelHexRecordWriter(size, dropBytes);

		AddressSet set = new AddressSet(addrSetView);

		MemoryBlock[] blocks = memory.getBlocks();
		for (MemoryBlock block : blocks) {
			if (!block.isInitialized() ||
				block.getStart().getAddressSpace() != addressSpaceOption.getValue()) {
				set.delete(new AddressRangeImpl(block.getStart(), block.getEnd()));
			}
		}

		AddressIterator addresses = set.getAddresses(true);
		while (addresses.hasNext()) {
			Address address = addresses.next();
			byte b = memory.getByte(address);
			writer.addByte(address, b);
		}

		Address entryPoint = null;
		AddressIterator entryPointIterator =
			program.getSymbolTable().getExternalEntryPointIterator();
		while (entryPoint == null && entryPointIterator.hasNext()) {
			Address address = entryPointIterator.next();
			if (set.contains(address)) {
				entryPoint = address;
			}
		}
		return writer.finish(entryPoint);
	}
}
