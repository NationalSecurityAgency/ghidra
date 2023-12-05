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
package ghidra.bsfv;

import java.util.*;

import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.signature.*;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.util.Msg;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.task.TaskMonitor;

class BsfvTableModel extends AddressBasedTableModel<BsfvRowObject> {

	private BSimFeatureVisualizerPlugin plugin;
	private HighFunction hfunction;
	private Map<SequenceNumber, PcodeOpAST> seqToPcode;
	private Map<Integer, String> blockIndexToCallString;
	private ArrayList<DebugSignature> signatures;
	private Set<PcodeOpAST> featuredOps;

	public static boolean DEBUG = false;

	public BsfvTableModel(BSimFeatureVisualizerPlugin plugin, Program program) {
		super("BSim Feature Visualizer", plugin.getTool(), program, null);
		this.plugin = plugin;
	}

	@Override
	protected TableColumnDescriptor<BsfvRowObject> createTableColumnDescriptor() {
		TableColumnDescriptor<BsfvRowObject> descriptor = new TableColumnDescriptor<>();
		descriptor.addHiddenColumn(new AddressTableColumn());
		descriptor.addVisibleColumn(new OpSequenceNumberTableColumn(), 1, true);
		descriptor.addVisibleColumn(new BSimFeatureTableColumn(), 2, true);
		descriptor.addVisibleColumn(new BSimFeatureTypeTableColumn());
		descriptor.addVisibleColumn(new PcodeOpNameTableColumn());
		descriptor.addVisibleColumn(new BaseVarnodeTableColumn());
		descriptor.addVisibleColumn(new BasicBlockAddressTableColumn());
		descriptor.addVisibleColumn(new PreviousOpInfoTableColumn());
		descriptor.addHiddenColumn(new BasicBlockIndexColumn());
		return descriptor;
	}

	@Override
	protected void doLoad(Accumulator<BsfvRowObject> accumulator, TaskMonitor monitor)
			throws CancelledException {

		if (plugin.getCurrentProgram() == null) {
			return;
		}

		Function function = plugin.getFunction();
		if (function == null) {
			return; // not inside a function
		}

		if (!decompile(function, monitor)) {
			return;
		}

		featuredOps = new HashSet<>();
		//process the debug signatures: 
		//tie them to the pcodeopast/basic blocks from the high function
		//create row of table for each feature
		for (int i = 0; i < signatures.size(); ++i) {
			int hash = signatures.get(i).hash;
			SequenceNumber seq = null;
			BSimFeatureType type = null;
			Varnode vn = null;
			PcodeOpAST pcode = null;
			PcodeOpAST previousPcode = null;
			Address basicBlockStart = null;
			Integer blockIndex = null;
			if (signatures.get(i) instanceof VarnodeSignature varSig) {
				seq = varSig.seqNum;
				type = BSimFeatureType.DATA_FLOW;
				vn = varSig.vn;
				pcode = seqToPcode.get(varSig.seqNum);
				if (pcode != null && pcode.getParent() != null) {
					basicBlockStart =
						pcode.getParent().getIterator().next().getSeqnum().getTarget();
					featuredOps.add(pcode);
				}
				if (pcode == null) {
					Msg.info(this, "null pcode for feature " + hash + ", op = " + varSig.opcode +
						", seq = " + seq);
				}
				else {
					if (!pcode.getMnemonic().equals(varSig.opcode)) {
						Msg.info(this, "op mis-match at " + seq + ", varSig = " + varSig.opcode +
							", pcode = " + pcode.getMnemonic());
					}
				}
			}
			else if (signatures.get(i) instanceof CopySignature copySig) {
				blockIndex = copySig.index;
				type = BSimFeatureType.COPY_SIG;
				basicBlockStart = hfunction.getBasicBlocks().get(blockIndex).getStart();
				seq = new SequenceNumber(basicBlockStart, 0);
			}
			else {
				BlockSignature blockSig = (BlockSignature) signatures.get(i);
				basicBlockStart = blockSig.blockSeq;
				blockIndex = blockSig.index;
				if (blockSig.opSeq == null) {
					// If opSeq is null, then previousOpSeq is null as well
					seq = new SequenceNumber(blockSig.blockSeq, 0);
					// This is a pure control-flow feature
					type = BSimFeatureType.CONTROL_FLOW;
					basicBlockStart = blockSig.blockSeq;
				}
				else if (blockSig.previousOpSeq == null) {	// If we only have the primary op
					seq = blockSig.opSeq;
					// This is the first root op, mixed with control-flow info
					type = BSimFeatureType.COMBINED;
					basicBlockStart = blockSig.blockSeq;
					pcode = seqToPcode.get(blockSig.opSeq);
				}
				else {
					seq = blockSig.opSeq;
					// This is two consecutive root ops, mixed together
					type = BSimFeatureType.DUAL_FLOW;
					basicBlockStart = blockSig.blockSeq;
					pcode = seqToPcode.get(blockSig.opSeq);
					previousPcode = seqToPcode.get(blockSig.previousOpSeq);
				}
			}
			accumulator.add(new BsfvRowObject(hash, seq, vn, pcode, previousPcode, type,
				basicBlockStart, blockIndex));
			if (DEBUG) {
				Msg.debug(this, i + ": " + seq + " " + Integer.toUnsignedString(hash, 16));
			}
		}
	}

	@Override
	public Address getAddress(int row) {
		return getRowObject(row).getAddress();
	}

	/**
	 * Returns the {@link PcodeOpAST} object at the specified row.
	 * @param row row index
	 * @return pcodeop
	 */
	public PcodeOpAST getOpAt(int row) {
		return getRowObject(row).getPcodeOpAST();
	}

	/**
	 * Returns the previous {@link PcodeOpAST} object at the specified row.
	 * @param row row index
	 * @return previous pcodeop
	 */
	public PcodeOpAST getPreviousOpAt(int row) {
		return getRowObject(row).getPreviousPcodeOpAST();
	}

	/**
	 * Returns the {@link BSimFeatureType} at the specified row
	 * @param row row index
	 * @return bsim feature type
	 */
	public BSimFeatureType getFeatureTypeAt(int row) {
		return getRowObject(row).getBSimFeatureType();
	}

	/**
	 * Returns the basic block index at the specified row
	 * @param row row index
	 * @return basic block index
	 */
	public Integer getBlockIndexAt(int row) {
		return getRowObject(row).getBlockIndex();
	}

	/**
	 * Returns the start address of the basic block at the specified row
	 * @param row row index
	 * @return start of block
	 */
	public Address getBasicBlockStart(int row) {
		return getRowObject(row).getBasicBlockStart();
	}

	/**
	 * Returns the {@link HighFunction} of the function whose features currently populate the table.
	 * @return high function
	 */
	public HighFunction getHighFunction() {
		return hfunction;
	}

	/**
	 * Returns an unmodifiable view of the set of pcode ops whose outputs are the base varnodes 
	 * of DATA_FLOW features.
	 * @return pcode ops corresponding to DATA_FLOW features
	 */
	public Set<PcodeOpAST> getFeaturedOps() {
		return Collections.unmodifiableSet(featuredOps);
	}

	/**
	 * Returns the "call string" of a basic block, which represents the number and ordering
	 * of CALL and CALLIND pcode ops with the block.
	 * @param index block index
	 * @return call string
	 */
	public String getCallString(int index) {
		return blockIndexToCallString.get(index);
	}

	/**
	 * Sets the current program and reloads the table data.
	 * @param p program
	 */
	public void reload(Program p) {
		setProgram(p);
		reload();
	}

	@Override
	public void setProgram(Program program) {
		if (this.program != program) {
			this.program = program;
			clearData();
		}
	}

	private boolean decompile(Function function, TaskMonitor monitor) {

		DecompInterface decompiler = null;
		try {
			decompiler = getConfiguredDecompiler();
			if (!decompiler.openProgram(plugin.getCurrentProgram())) {
				Msg.info(this, "Unable to initalize the Decompiler interface");
				Msg.info(this, decompiler.getLastMessage());
				return false;
			}
			int decompilerTimeout = plugin.getDecompilerTimeout();
			//first decompile the function to get the HighFunction 
			DecompileResults decompRes =
				decompiler.decompileFunction(function, decompilerTimeout, monitor);
			hfunction = decompRes.getHighFunction();
			if (hfunction == null) {
				Msg.info(this, "null HighFunction for " + function.getName());
				return false;
			}
			//populate the map from block indices to call strings and
			//create a map from SequenceNumbers to PcodeOps
			//needed since the DebugSignature objects only contain the sequence number
			seqToPcode = new HashMap<>();
			blockIndexToCallString = new HashMap<>();
			for (PcodeBlockBasic block : hfunction.getBasicBlocks()) {
				StringBuilder sb = new StringBuilder();
				Iterator<PcodeOp> pcodeOpIter = block.getIterator();
				while (pcodeOpIter.hasNext()) {
					PcodeOpAST op = (PcodeOpAST) pcodeOpIter.next();
					seqToPcode.put(op.getSeqnum(), op);
					if ((op.getOpcode() == PcodeOp.CALL) || (op.getOpcode() == PcodeOp.CALLIND)) {
						if (sb.length() > 0) {
							sb.append(",");
						}
						sb.append(op.getMnemonic());
					}
				}
				if (sb.length() == 0) {
					sb.append(BSimFeatureGraphType.EMPTY_CALL_STRING);
				}
				blockIndexToCallString.put(block.getIndex(), sb.toString());
			}

			//next use the decompiler to get the debug BSim feature information
			signatures = decompiler.debugSignatures(function, decompilerTimeout, null);
			if (signatures == null) {
				Msg.info(this, "Null sigres for function " + function.getName());
				return false;
			}
		}
		finally {
			if (decompiler != null) {
				decompiler.closeProgram();
				decompiler.dispose();
			}
		}
		return true;
	}

	private DecompInterface getConfiguredDecompiler() {
		DecompInterface decompiler = new DecompInterface();
		decompiler.setOptions(new DecompileOptions());
		decompiler.toggleSyntaxTree(true);
		decompiler.setSimplificationStyle("normalize");
		decompiler.setSignatureSettings(plugin.getSignatureSettings());
		return decompiler;
	}

	//==============================================================================================
	// Inner Classes (Table Columns)
	//==============================================================================================

	private class PreviousOpInfoTableColumn
			extends AbstractDynamicTableColumn<BsfvRowObject, String, Object> {

		@Override
		public String getColumnName() {
			return "Previous Op Info";
		}

		@Override
		public String getValue(BsfvRowObject rowObject, Settings settings, Object data,
				ServiceProvider sProvider) throws IllegalArgumentException {
			PcodeOp prev = rowObject.getPreviousPcodeOpAST();
			if (prev == null) {
				return null;
			}
			return prev.getMnemonic() + ": " + prev.getSeqnum().toString();
		}

	}

	private class PcodeOpNameTableColumn
			extends AbstractDynamicTableColumn<BsfvRowObject, String, Object> {

		@Override
		public String getColumnName() {
			return "Pcode Op Name";
		}

		@Override
		public String getValue(BsfvRowObject rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.getOpMnemonic();
		}
	}

	private class BaseVarnodeTableColumn
			extends AbstractDynamicTableColumn<BsfvRowObject, String, Object> {

		@Override
		public String getColumnName() {
			return "Base Varnode";
		}

		@Override
		public String getValue(BsfvRowObject rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			if (rowObject.getBaseVarnode() != null) {
				return rowObject.getBaseVarnode().toString(program.getLanguage());
			}
			return null;
		}
	}

	private class BSimFeatureTableColumn
			extends AbstractDynamicTableColumn<BsfvRowObject, BsfvFeatureColumnObject, Object> {

		@Override
		public String getColumnName() {
			return "Feature";
		}

		@Override
		public BsfvFeatureColumnObject getValue(BsfvRowObject rowObject, Settings settings,
				Object data, ServiceProvider services) throws IllegalArgumentException {
			return rowObject.getFeature();
		}
	}

	private class OpSequenceNumberTableColumn
			extends AbstractDynamicTableColumn<BsfvRowObject, SequenceNumber, Object> {

		@Override
		public String getColumnName() {
			return "Op Sequence Number";
		}

		@Override
		public SequenceNumber getValue(BsfvRowObject rowObject, Settings settings, Object data,
				ServiceProvider sProvider) throws IllegalArgumentException {
			return rowObject.getSeq();
		}

	}

	private class BasicBlockAddressTableColumn
			extends AbstractDynamicTableColumn<BsfvRowObject, Address, Object> {

		@Override
		public String getColumnName() {
			return "Basic Block Start";
		}

		@Override
		public Address getValue(BsfvRowObject rowObject, Settings settings, Object data,
				ServiceProvider sProvider) throws IllegalArgumentException {
			return rowObject.getBasicBlockStart();
		}

	}

	private class AddressTableColumn
			extends AbstractDynamicTableColumn<BsfvRowObject, Address, Object> {

		@Override
		public String getColumnName() {
			return "Address";
		}

		@Override
		public Address getValue(BsfvRowObject rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.getAddress();
		}
	}

	private class BSimFeatureTypeTableColumn
			extends AbstractDynamicTableColumn<BsfvRowObject, String, Object> {

		@Override
		public String getColumnName() {
			return "Feature Type";
		}

		@Override
		public String getValue(BsfvRowObject rowObject, Settings settings, Object data,
				ServiceProvider sProvider) throws IllegalArgumentException {
			return rowObject.getBSimFeatureType().toString();
		}

	}

	private class BasicBlockIndexColumn
			extends AbstractDynamicTableColumn<BsfvRowObject, Integer, Object> {

		@Override
		public String getColumnName() {
			return "Block Index";
		}

		@Override
		public Integer getValue(BsfvRowObject rowObject, Settings settings, Object data,
				ServiceProvider sProvider) throws IllegalArgumentException {
			return rowObject.getBlockIndex();
		}

	}
}
