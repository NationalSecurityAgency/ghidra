package ghidra.app.plugin.prototype.MicrosoftCodeAnalyzerPlugin;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.format.pe.ControlFlowGuard;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.cmd.Command;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Finds Control Flow Guard data structures (annotated by the Importer) within a Windows program. 
 * It disassembles and creates functions from the CFG Tables.
 */
public class CfgAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "Control Flow Guard Analyzer";
	private static final String DESCRIPTION =
			"Creates functions from GuardCFFunctionTable if present.";
	private Address cfgTableAddr = null;

	public CfgAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setSupportsOneTimeAnalysis();
		// TODO(marpie): the perfect time to run would be after the PDB importer, but 
		//                how could that be specified? For now, just use the same as the RTTI Analyzer.
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.before().before());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return checkCfgPresence(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		if (cfgTableAddr == null) {
			log.appendMsg(this.getName(), "Couldn't find Control Flow Guard tables.");
			return true;
		}

		Listing listing = program.getListing();

		Data tableData = listing.getDataAt(cfgTableAddr);
		if (!tableData.isArray() || (tableData.getNumComponents() < 1)) {
			log.appendMsg(this.getName(), "Control Flow Guard table seems to be empty.");
			return true;
		}

		FunctionManager funcMgr = program.getFunctionManager();
		Command cmd = null;
		for (Address target : getFunctionAddressesFromTable(program, tableData)) {
			if (funcMgr.getFunctionAt(target) != null) {
				// if there already is a function, just bail...
				continue;
			}
			cmd = new DisassembleCommand(target, null, true);
			cmd.applyTo(program);

			cmd = new CreateFunctionCmd(target);
			cmd.applyTo(program);
		}

		return true;
	}

	private boolean checkCfgPresence(Program program) {
		SymbolTable table = program.getSymbolTable();
		for (Symbol symbol : table.getSymbols(ControlFlowGuard.GuardCFFunctionTableName)) {
			if ((symbol.getSymbolType() == SymbolType.LABEL) && (symbol.getSource() == SourceType.IMPORTED)) {
				cfgTableAddr = symbol.getAddress();
				return true;
			}
		}
		return false;
	}

	private List<Address> getFunctionAddressesFromTable(Program program, Data table) {
		List<Address> list = new ArrayList<Address>();

		Address imageBase = program.getImageBase();
		Memory mem = program.getMemory();
		long offset = 0;
		for (int i = 0; i < table.getNumComponents(); i++) {
			Data entry = table.getComponent(i);
			try {
				offset = mem.getInt(entry.getAddress());
			} catch (MemoryAccessException e) {
				// just assume everything else will also fail and bail here
				break;
			}
			list.add(imageBase.add(offset));
		}
		return list;
	}
}
