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
package ghidra.app.plugin.core.datamgr.actions;

import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.tree.GTree;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesActionContext;
import ghidra.app.plugin.core.datamgr.tree.ArchiveNode;
import ghidra.app.plugin.core.datamgr.tree.BuiltInArchiveNode;
import ghidra.app.plugin.core.datamgr.tree.DataTypeArchiveGTree;
import ghidra.app.plugin.core.datamgr.tree.DataTypeNode;
import ghidra.app.plugin.core.datamgr.tree.DataTypeTreeNode;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypeManagerChangeListener;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.SourceArchive;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnionDataType;
import ghidra.util.InvalidNameException;
import ghidra.util.StringUtilities;
import ghidra.util.exception.DuplicateNameException;

public class CreateLPUnionStructAction extends DockingAction implements DataTypeManagerChangeListener {

	private static final String ACTION_NAME = "LPUnion4Pointers";
	protected static final String OFFSET_NAME = "__offset__";
	protected static final String SEGMENT_NAME = "__segment__";
	protected static final String NEAR_NAME = "__np__";
	protected static final String FAR_NAME = "__lp__";
	protected static final CategoryPath GHIDRA_LP_UNION_CATEGORY = new CategoryPath("/_GhidraLpUnions");
	protected static final CategoryPath GHIDRA_LP_UNION_STRUCT_CATEGORY = new CategoryPath("/_GhidraLpUnions/_seg");

	protected static final String UNDEFINED = "undefined";
	protected static final String NEAR_P = " * ".concat(NEAR_NAME);
	protected static final String FAR_LP = " far * ".concat(FAR_NAME);
	protected static final String UNION_PREFIX = "LP";
	protected static final String SEGMENT_PREFIX = "__seg";

	protected DataTypeManagerPlugin plugin;

	public CreateLPUnionStructAction(DataTypeManagerPlugin plugin) {
		super("Create " + ACTION_NAME, plugin.getName());
		this.plugin = plugin;
		plugin.addDataTypeManagerChangeListener(this);
		setPopupMenuData(new MenuData(new String[] { "New", ACTION_NAME }, null, "Create"));
	}

	@Override
	public void actionPerformed(ActionContext context) {
		DataTypeArchiveGTree gTree = (DataTypeArchiveGTree) context.getContextObject();
		TreePath[] selectionPaths = gTree.getSelectionPaths();
		DataTypeNode dataTypeNode = (DataTypeNode) selectionPaths[0].getLastPathComponent();
		DataType baseDataType = dataTypeNode.getDataType();

		DerivativeDataTypeInfo info =
			new DerivativeDataTypeInfo(plugin, gTree, dataTypeNode, baseDataType);
		DataTypeManager dtMgr = info.getDataTypeManager();
		DataType ut = CreateNewLPUnion(dtMgr, baseDataType);
	}

	public DataType CreateNewLPUnion(DataTypeManager dtMgr, DataType dt) {
		int transactionID = dtMgr.startTransaction("Create Associated DataTypes");
		try {
			String name = dt.getName();
			String unionName = UNION_PREFIX.concat(name);
			String structName = SEGMENT_PREFIX.concat(unionName);
			String nearPtrType = dt.getCategoryPath().getName().concat("/").concat(name).concat(" *");
			String farPtrType = dt.getCategoryPath().getName().concat("/").concat(name).concat(" *32");

			StructureDataType structPtrComp = new StructureDataType(GHIDRA_LP_UNION_STRUCT_CATEGORY, structName , 0, dtMgr);
			DataType nearPDt = getPointerType(dtMgr, dt, nearPtrType, 2);
			structPtrComp.add(nearPDt , -1, OFFSET_NAME, "");
			try {
				structPtrComp.add(dtMgr.getDataType("/SegmentCodeAddress"), 2, SEGMENT_NAME, "");
			}
			catch (Exception e) {
				DataTypeManager[] dataTypeManagers = plugin.getDataTypeManagers();
				for (DataTypeManager dataTypeManager : dataTypeManagers) {
					try {
						structPtrComp.add(dataTypeManager.getDataType("/SegmentCodeAddress"), 2, SEGMENT_NAME, "");
						break;
					}
					catch (Exception e1) {
						// Try next!
					}
				}
			}

			UnionDataType ut = new UnionDataType(GHIDRA_LP_UNION_CATEGORY, UNION_PREFIX.concat(name));
			ut.add(structPtrComp, 4, NEAR_NAME, "");
			DataType farPDt = getPointerType(dtMgr, dt, farPtrType, 4);
			ut.add(farPDt, 4, FAR_NAME, "");

			DataType newDt = dtMgr.addDataType(ut, plugin.getConflictHandler());
			dtMgr.endTransaction(transactionID, true);

			return newDt;
		} catch (DuplicateNameException e) {
			dtMgr.endTransaction(transactionID, false);
			return null;
		}
	}

	/**
	 * Ensure pointer to data type exists, create if not.
	 *
	 * @param dtMgr
	 * @param dt
	 * @param ptrType
	 * @param size
	 * @return
	 * @throws DuplicateNameException
	 */
	private static DataType getPointerType(DataTypeManager dtMgr, DataType dt, String ptrType, int size)
			throws DuplicateNameException {
		if (!ptrType.startsWith("/")) {
			ptrType = "/" + ptrType;
		}
		DataType pDt = dtMgr.getDataType(ptrType);
		if (null == pDt) {
			pDt = new PointerDataType(dt, size, dtMgr);
			pDt.setCategoryPath(dt.getCategoryPath());
		}
		return pDt;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		DataTypeTreeNode node = getDataTypeNode(context);
		if (node == null) {
			return false;
		}

		ArchiveNode archiveNode = node.getArchiveNode();
		if (archiveNode == null) {
			// this can happen as the tree is changing
			return false;
		}

		boolean enabled = archiveNode.isModifiable();
		if (archiveNode instanceof BuiltInArchiveNode) {
			// these will be put into the program archive
			enabled = true;
		}

		// update the menu item to add the name of the item we are working on
		if (enabled) {
			String dtName = node.getName();
			dtName = StringUtilities.trim(dtName, 10);
			MenuData newMenuData =
				new MenuData(new String[] { "New", ACTION_NAME + " to " + dtName }, null, "Create");
			setPopupMenuData(newMenuData);
		}

		return enabled;
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		DataTypeNode node = getDataTypeNode(context);
		if (node == null) {
			return false;
		}

		DataType dataType = node.getDataType();
		DataTypeManager dataTypeManager = dataType.getDataTypeManager();
		if (dataTypeManager instanceof BuiltInDataTypeManager) {
			DataTypeManager manager = plugin.getProgramDataTypeManager();
			if (manager == null) {
				return false; // no program open; can't work from the built-in in this case
			}
		}

		return true;
	}

	private DataTypeNode getDataTypeNode(ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return null;
		}

		Object contextObject = context.getContextObject();
		GTree gtree = (GTree) contextObject;
		TreePath[] selectionPaths = gtree.getSelectionPaths();
		if (selectionPaths.length != 1) {
			return null;
		}

		DataTypeTreeNode node = (DataTypeTreeNode) selectionPaths[0].getLastPathComponent();
		if (!(node instanceof DataTypeNode)) {
			return null;
		}
		return (DataTypeNode) node;
	}

	@Override
	public void categoryAdded(DataTypeManager dtm, CategoryPath path) {
		// TODO Auto-generated method stub

	}

	@Override
	public void categoryRemoved(DataTypeManager dtm, CategoryPath path) {
		// TODO Auto-generated method stub

	}

	@Override
	public void categoryRenamed(DataTypeManager dtm, CategoryPath oldPath, CategoryPath newPath) {
		// TODO Auto-generated method stub

	}

	@Override
	public void categoryMoved(DataTypeManager dtm, CategoryPath oldPath, CategoryPath newPath) {
		// TODO Auto-generated method stub

	}

	@Override
	public void dataTypeAdded(DataTypeManager dtm, DataTypePath path) {
		// TODO Auto-generated method stub

	}

	@Override
	public void dataTypeRemoved(DataTypeManager dtm, DataTypePath path) {
		// TODO Auto-generated method stub

	}

	@Override
	public void dataTypeRenamed(DataTypeManager dtm, DataTypePath oldPath, DataTypePath newPath) {
		String oldName = oldPath.getDataTypeName();
		String oldUnionName = UNION_PREFIX.concat(oldName);
		String oldStructName = SEGMENT_PREFIX.concat(oldUnionName);
		DataType oldUnion = dtm.getDataType(GHIDRA_LP_UNION_CATEGORY, oldUnionName);
		DataType oldStruct = dtm.getDataType(GHIDRA_LP_UNION_STRUCT_CATEGORY, oldStructName);
		if ((null == oldUnion) || (null == oldStruct)) return;

		String newName = newPath.getDataTypeName();
		String newUnionName = UNION_PREFIX.concat(newName);
		String newStructName = SEGMENT_PREFIX.concat(newUnionName);
		int transactionID = dtm.startTransaction("Rename Associated DataType");
		try {
			oldStruct.setName(newStructName);
			oldUnion.setName(newUnionName);
			dtm.endTransaction(transactionID, true);
		} catch (InvalidNameException | DuplicateNameException e) {
			// TODO Auto-generated catch block
			dtm.endTransaction(transactionID, false);
			e.printStackTrace();
		}
	}

	@Override
	public void dataTypeMoved(DataTypeManager dtm, DataTypePath oldPath, DataTypePath newPath) {
		// TODO Auto-generated method stub

	}

	@Override
	public void dataTypeChanged(DataTypeManager dtm, DataTypePath path) {
		// TODO Auto-generated method stub

	}

	@Override
	public void dataTypeReplaced(DataTypeManager dtm, DataTypePath oldPath, DataTypePath newPath,
			DataType newDataType) {
		// TODO Auto-generated method stub

	}

	@Override
	public void favoritesChanged(DataTypeManager dtm, DataTypePath path, boolean isFavorite) {
		// TODO Auto-generated method stub

	}

	@Override
	public void sourceArchiveChanged(DataTypeManager dataTypeManager, SourceArchive sourceArchive) {
		// TODO Auto-generated method stub

	}

	@Override
	public void sourceArchiveAdded(DataTypeManager dataTypeManager, SourceArchive sourceArchive) {
		// TODO Auto-generated method stub

	}

	@Override
	public void programArchitectureChanged(DataTypeManager dataTypeManager) {
		// TODO Auto-generated method stub

	}
}
