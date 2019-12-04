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

import java.util.List;

import ghidra.app.cmd.function.CallDepthChangeInfo;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.program.util.OperandFieldLocation;
import ghidra.program.util.ProgramLocation;

public class CreateDefaultReferenceAction extends ListingContextAction {

	static String DEFAULT_MENU_ITEM_NAME = "Create Default Reference";
	static String MEMORY_MENU_ITEM_NAME = "Create Memory Reference";
	static String STACK_MENU_ITEM_NAME = "Create Stack Reference";
	static String REGISTER_MENU_ITEM_NAME = "Create Register Reference";

	static final int UNKNOWN_REF_CLASS = -1;
	static final int MEMORY_REF_CLASS = 0;
	static final int STACK_REF_CLASS = 1;
	static final int REGISTER_REF_CLASS = 2;

	private ReferencesPlugin plugin;

	private ListingActionContext context;
	private int refClass = UNKNOWN_REF_CLASS;
	private Register reg;
	private Address memAddr;
	private int stackOffset;

	public CreateDefaultReferenceAction(ReferencesPlugin plugin) {
		super("Create Default Reference", plugin.getName());
		this.plugin = plugin;
	}

	@Override
	protected void actionPerformed(ListingActionContext context) {
		if (this.context != context && !isEnabledForContext(context)) {
			return;
		}
		OperandFieldLocation opLoc = (OperandFieldLocation) context.getLocation();
		switch (refClass) {
			case MEMORY_REF_CLASS:
				CodeUnit cu =
					opLoc.getProgram().getListing().getCodeUnitContaining(opLoc.getAddress());
				RefType refType = (cu instanceof Instruction) ? null : RefType.DATA;
				plugin.addDefaultReference(context.getProgram(), opLoc.getAddress(),
					opLoc.getOperandIndex(), memAddr, refType);
				break;
			case STACK_REF_CLASS:
				plugin.addDefaultReference(context.getProgram(), opLoc.getAddress(),
					opLoc.getOperandIndex(), stackOffset);
				break;
			case REGISTER_REF_CLASS:
				plugin.addDefaultReference(context.getProgram(), opLoc.getAddress(),
					opLoc.getOperandIndex(), reg);
				break;
		}
	}

	/**
	 * Invalidate cached context
	 */
	private void invalidateContext() {
		context = null;
		refClass = UNKNOWN_REF_CLASS;
		memAddr = null;
		reg = null;
	}

	@Override
	protected boolean isAddToPopup(ListingActionContext context) {
		ProgramLocation loc = context.getLocation();
		return (loc instanceof OperandFieldLocation);
	}

	@Override
	protected boolean isEnabledForContext(ListingActionContext context) {

		invalidateContext();
		boolean actionOK = false;

		ProgramLocation loc = context.getLocation();
		if (loc instanceof OperandFieldLocation) {
			OperandFieldLocation opLoc = (OperandFieldLocation) context.getLocation();
			this.context = context;

			Program program = context.getProgram();
			opLoc = (OperandFieldLocation) loc;
			Address addr = opLoc.getAddress();
			int opIndex = opLoc.getOperandIndex();

			CodeUnit cu = program.getListing().getCodeUnitContaining(addr);
			if (cu != null) {

				if (cu instanceof Data) {
					Data data = ((Data) cu).getComponent(opLoc.getComponentPath());
					Object obj = data.getValue();
					if (obj instanceof Scalar) {
						refClass = MEMORY_REF_CLASS;
						actionOK = initMemoryAddress(program.getAddressFactory(),
							((Scalar) obj).getUnsignedValue());
					}
					else if (obj instanceof Address) {
						memAddr = (Address) obj;
						refClass = MEMORY_REF_CLASS;
						actionOK = true;
					}
				}
				else {
					Instruction instr = (Instruction) cu;
					int subOpIndex = opLoc.getSubOperandIndex();
					List<?> opList = instr.getDefaultOperandRepresentationList(opIndex);
					if (opList == null || subOpIndex < 0 || opList.size() <= subOpIndex) {
						return false;
					}

					Object opObj = opList.get(subOpIndex);
					if (opObj instanceof Address) {
						Address opAddr = (Address) opObj;
						if (opAddr.isMemoryAddress()) {
							memAddr = opAddr;
							refClass = MEMORY_REF_CLASS;
							actionOK = true;
						}
					}
					else {
						Function f = program.getFunctionManager().getFunctionContaining(addr);
						if (f != null) {
							if (opObj instanceof Scalar) {
								CallDepthChangeInfo cdInfo = new CallDepthChangeInfo(f);
								stackOffset = cdInfo.getStackOffset(instr, opIndex);
								if (stackOffset != Function.INVALID_STACK_DEPTH_CHANGE) {
									refClass = STACK_REF_CLASS;
									Object[] opObjs = instr.getOpObjects(opIndex);
									for (int i = 0; !actionOK && i < opObjs.length; i++) {
										if (opObjs[i] instanceof Register) {
											int regDepth =
												cdInfo.getRegDepth(addr, (Register) opObjs[i]);
											actionOK =
												(regDepth != Function.INVALID_STACK_DEPTH_CHANGE &&
													regDepth != Function.UNKNOWN_STACK_DEPTH_CHANGE);
										}
									}
								}
							}
							else if (opObj instanceof VariableOffset) {
								VariableOffset varOff = (VariableOffset) opObj;
								Object replacedObj = varOff.getReplacedElement();
								if ((replacedObj instanceof Register) &&
									RefTypeFactory.getDefaultRegisterRefType(instr,
										(Register) replacedObj, opIndex).isWrite()) {
									refClass = REGISTER_REF_CLASS;
									reg = (Register) replacedObj;
									actionOK = true;
								}
							}
							else if (opObj instanceof Register) {
								refClass = REGISTER_REF_CLASS;
								reg = (Register) opObj;
								actionOK = true;
							}

						}
						if (refClass == UNKNOWN_REF_CLASS && opObj instanceof Scalar) {
							// Try memory reference
							refClass = MEMORY_REF_CLASS;
							actionOK = initMemoryAddress(program.getAddressFactory(),
								((Scalar) opObj).getUnsignedValue());
						}
					}
				}

				if (actionOK) {
					// Make sure default ref does not already exist
					Reference[] refs =
						program.getReferenceManager().getReferencesFrom(addr, opIndex);
					if (refs.length != 0) {
						Address toAddr = refs[0].getToAddress();
						if (toAddr.isExternalAddress()) {
							actionOK = false;
						}
						else {
							switch (refClass) {
								case MEMORY_REF_CLASS:
									if (memAddr != null && toAddr.isMemoryAddress()) {
										for (int i = 0; i < refs.length; i++) {
											if (refs[i].getSource() != SourceType.DEFAULT &&
												memAddr.equals(toAddr)) {
												actionOK = false;
												break;
											}
										}
									}
									break;
								case STACK_REF_CLASS:
									if (refs[0].isStackReference()) {
										actionOK = false;
									}
									break;
								case REGISTER_REF_CLASS:
									if (refs[0].getToAddress().isRegisterAddress()) {
										actionOK = false;
									}
									break;
							}
						}
					}
				}

			}
		}
		updatePopupMenuPath(actionOK);
		return actionOK;
	}

	private boolean initMemoryAddress(AddressFactory addrFactory, long offset) {
		AddressSpace contextAddrSpace = context.getAddress().getAddressSpace();
		try {
			memAddr = contextAddrSpace.getAddress(offset, true);
			return true;
		}
		catch (AddressOutOfBoundsException ei) {
			// try the default space!
		}
		AddressSpace defaultSpace = addrFactory.getDefaultAddressSpace();

		if (contextAddrSpace != defaultSpace) {
			try {
				memAddr = defaultSpace.getAddress(offset, true);
				return true;
			}
			catch (AddressOutOfBoundsException ei) {
				// ignore
			}
		}
		return false;
	}

	private void updatePopupMenuPath(boolean actionOK) {
		if (actionOK) {
			switch (refClass) {
				case MEMORY_REF_CLASS:
					getPopupMenuData().setMenuItemName(MEMORY_MENU_ITEM_NAME);
					break;
				case STACK_REF_CLASS:
					getPopupMenuData().setMenuItemName(STACK_MENU_ITEM_NAME);
					break;
				case REGISTER_REF_CLASS:
					getPopupMenuData().setMenuItemName(REGISTER_MENU_ITEM_NAME);
					break;
				default:
					getPopupMenuData().setMenuItemName(DEFAULT_MENU_ITEM_NAME);
			}
		}
		else {
			getPopupMenuData().setMenuItemName(DEFAULT_MENU_ITEM_NAME);
		}
	}

	int getDefaultRefClass() {
		return refClass;
	}

}
