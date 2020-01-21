package ghidra.app.util.bin.format.stabs;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.DefaultDataTypeManagerService;
import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.util.data.DataTypeParser;

/**
 * Exception implementation of the StabSymbolDescriptor
 */
public class StabsExceptionSymbolDescriptor extends AbstractStabsSymbolDescriptor {

	private final DataTypeParser parser;
	private final DataTypeManagerService service;

	/**
	 * Constructs a new StabsExceptionSymbolDescriptor
	 * @param stab the portion of the stab containing this descriptor
	 * @param file the file containing this descriptor
	 * @throws StabsParseException if the descriptor or one it relies on is invalid
	 */
	StabsExceptionSymbolDescriptor(String stab, StabsFile file) {
		super(stab, file);
		PluginTool tool =
			AutoAnalysisManager.getAnalysisManager(file.getProgram()).getAnalysisTool();
		if (tool != null) {
			this.service = tool.getService(DataTypeManagerService.class);
		} else {
			// if tool == null then we're in headless mode
			this.service = new DefaultDataTypeManagerService();
		}
		this.parser = new DataTypeParser(service, DataTypeParser.AllowedDataTypes.ALL);
	}

	@Override
	public DataType getDataType() {
		try {
			// return the exceptions datatype if known
			DataType dt = parser.parse(name);
			return dt;
		}
		catch (Exception e) {
			// if we don't have it then return null
		}
		return null;
	}

	@Override
	public StabsSymbolDescriptorType getSymbolDescriptorType() {
		return StabsSymbolDescriptorType.EXCEPTION;
	}
}
