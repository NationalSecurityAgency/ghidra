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

import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.CorePluginPackage;
import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.util.HelpTopics;
import ghidra.framework.cmd.Command;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.exception.CancelledException;

/**
 *
 * Plugin to create offset tables based on a selection of data.  A dialog is
 * displayed so that the user can enter a base address and the 
 * data type size. Data of the appropriate type is created; a reference to 
 * the base address + offset is placed on the operand index for each data 
 * that was created. The offset is the value of the data type.
 *
 *
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Create Offset References",
	description = "Plugin to create offset tables based on a selection of data.  A dialog is "+
			"displayed so that the user can enter a base address and the "+
			"data type size. Data of the appropriate type is created; a reference to "+
			"the base address + offset is placed on the operand index for each data "+
			"that was created. The offset is the value of the data type."
)
//@formatter:on
public class OffsetTablePlugin extends Plugin {

	private DockingAction refAction;
	private int lastSelectedSize = 4;
	private boolean lastSigned = true;
	
	/**
	 * @param pluginName
	 * @param tool
	 */
	public OffsetTablePlugin(PluginTool tool) {
		super(tool);
		createActions();
	}


	private void createActions() {
		refAction = new ListingContextAction("Create Offset References", getName()) {
			@Override
            public void actionPerformed(ListingActionContext context) {
				showDialog(context);
			}
			@Override
			protected boolean isEnabledForContext(ListingActionContext context) {
				return (context.hasSelection() && context.getSelection().getInteriorSelection() == null);
			}
		};
		refAction.setHelpLocation(new HelpLocation(HelpTopics.REFERENCES, refAction.getName()));
		refAction.setPopupMenuData( 
			new MenuData(			new String[] {"References",   "Create Offset  References..." },null,"references" ) );



		tool.addAction(refAction);
	}

	private void showDialog(ListingActionContext context) {
		tool.setStatusInfo("");
		if (containsInstructions(context)) {
			tool.setStatusInfo(
				"Cannot create offset references: selection contains instructions", 
				true);
			return;
		}
		AddressFactory addressFactory = context.getProgram().getAddressFactory();
		Address minAddress = context.getSelection().getMinAddress();
		
		OffsetTableDialog dialog = new OffsetTableDialog(minAddress, addressFactory);
		dialog.setSelectedSize(lastSelectedSize);
		dialog.setSigned(lastSigned);
		try {
			dialog.showDialog(tool);
		} catch (CancelledException e) {
			return;
		}
		Address addr = dialog.getBaseAddress();
		boolean signed = dialog.isSigned();
											
		if (addr != null) {
			createOffsetTable(context, addr, dialog.getSelectedSize(), signed);
		}
	}
	DataType getDataType(int size) {
		switch (size) { 
			case 1: 
				return new ByteDataType();
			case 2:
				return new WordDataType();
			case 4:
				return new DWordDataType();
			case 8:
				return new QWordDataType();
		}
		return new WordDataType();
	}
	
	private void createOffsetTable(ListingActionContext context, Address baseAddr,
			int dataTypeSize, boolean signed) {
		
		Program program = context.getProgram();
		ProgramSelection selection = context.getSelection();
		lastSelectedSize = dataTypeSize;
		lastSigned = signed;
		
		DataType dt = getDataType(dataTypeSize);
		
		CompoundCmd cmd = new CompoundCmd("Create Offset References");
		// clear the selection
		AddressRangeIterator rangeIter = selection.getAddressRanges();
		while (rangeIter.hasNext()) {
			AddressRange range = rangeIter.next();
			cmd.add(new ClearCmd(range));
		}

		try {
			rangeIter = selection.getAddressRanges();
			while (rangeIter.hasNext()) {
				AddressRange range = rangeIter.next();
				Address addr = range.getMinAddress();
				Address endAddr = addr.add(dataTypeSize-1);
	
				while(range.contains(endAddr)) {
					cmd.add(new MyCreateDataCmd(addr, baseAddr, dt, signed));
					addr = addr.add(dataTypeSize);
					endAddr = addr.add(dataTypeSize-1);
				}
			}		
			tool.execute(cmd, program);
		}
		catch (AddressOutOfBoundsException e) {
			tool.setStatusInfo("Unable to create offset table: "+e);
		}
	}
	
	private boolean containsInstructions(ListingActionContext context) {
		Program program = context.getProgram();
		ProgramSelection selection = context.getSelection();
		InstructionIterator iter = program.getListing().getInstructions(selection, true);
		return iter.hasNext();
	}
		
	private class ClearCmd implements Command {
		private AddressRange range;
				
		ClearCmd(AddressRange range) {
			this.range = range;
		}
		
		public boolean applyTo(DomainObject obj) {
			Program program = (Program)obj;
			program.getListing().clearCodeUnits(range.getMinAddress(), 
									range.getMaxAddress(), false);
			return true;									
		}
		public String getName() {
			return "Clear Code Units";
		}
		public String getStatusMsg() {
			return null;
		}
	}

	private class MyCreateDataCmd extends CreateDataCmd {
		private Address dataAddr;
		private Address baseAddr;
		private String msg;
		private boolean signed;
		
		MyCreateDataCmd(Address dataAddr, Address baseAddr, DataType dt, boolean signed) {
			super(dataAddr, dt);
			this.dataAddr = dataAddr;
			this.baseAddr = baseAddr;
			this.signed = signed;
		}
		
		/* (non Javadoc)
		 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
		 */
		@Override
        public boolean applyTo(DomainObject obj) {
			if (super.applyTo(obj)) {
				Program program = (Program)obj;
				ReferenceManager refManager = program.getReferenceManager();
				Data data = program.getListing().getDefinedDataAt(dataAddr);
				if (data != null) {
					Scalar value = (Scalar)data.getValue();
					long offset = signed ? value.getSignedValue() : value.getUnsignedValue();
					try {
						data.addValueReference(baseAddr.add(offset), RefType.DATA); 
					} catch (AddressOutOfBoundsException e) {
						msg = e.getMessage();
						return false;
					}
					Reference primRef = 
						refManager.getPrimaryReferenceFrom(dataAddr, 0);
					if (primRef == null) {
						Reference[] refs = data.getValueReferences(); 
						refManager.setPrimary(refs[0], true);
					}
					return true;	
				}
				msg = "Data does not exist at " + dataAddr;
			}
			return false;
		}

		/* (non Javadoc)
		 * @see ghidra.framework.cmd.Command#getStatusMsg()
		 */
		@Override
        public String getStatusMsg() {
			if (msg != null) {
				return msg;
			}
			return super.getStatusMsg();
		}
	}

}
