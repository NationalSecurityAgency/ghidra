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
/*
 * Created on Aug 3, 2005
 */
package ghidra.app.plugin.prototype.dataArchiveUtilities;

import java.awt.Component;
import java.io.*;
import java.util.*;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import docking.widgets.filechooser.GhidraFileChooser;
import ghidra.MiscellaneousPluginPackage;
import ghidra.app.context.ListingActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.util.xml.DataTypesXmlMgr;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.*;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.filechooser.ExtensionFileFilter;
import ghidra.util.task.*;

//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = MiscellaneousPluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Convert data archives",
	description = "This plugin allows the user to convert GSL-generated archives back and forth to Ghidra data archives."
)
//@formatter:on
public class ArchiveConverterPlugin extends ProgramPlugin {

	private static final String IMPORT_EXPORT_GROUP = "Import/Export";
	final static String CONVERT_DATA = "Convert GSL- to data-archive";
	final static String GSL_ARCHIVE_DIR = "GSL Archive Directory";
	final static String GDT_ARCHIVE_DIR = "GDT Archive Directory";
	final static String ALIGNMENT_TAG = "added for alignment";

	final static String WRITE_GSL = "Write data-archive in GSL Format";

	private GhidraFileChooser fileChooser;
	private TypedefDataType dataUI;
	private Hashtable<String, DataType> dataTypes = new Hashtable<>();

	/**
	 * @param id
	 * @param plugintool
	 * @param consumeLocationChange
	 * @param consumeSelectionChange
	 */
	public ArchiveConverterPlugin(PluginTool plugintool) {
		super(plugintool, false, false);
		createActions();
	}

	public Program getProgram() {
		return currentProgram;
	}

	@Override
	public void dispose() {
		super.dispose();
	}

	/**
	 *
	 */
	private void createActions() {
		DockingAction parseAction = new DockingAction(CONVERT_DATA, getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				File gslArchive =
					chooseFile(tool.getToolFrame(), "Select GSL archive", GSL_ARCHIVE_DIR, "gsl");
				new TaskLauncher(new GSLParserTask(tool, gslArchive), tool.getToolFrame());
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return context.getContextObject() instanceof ListingActionContext;
			}
		};
		String[] menuPath = { ToolConstants.MENU_FILE, "Parse GSL Archive..." };
		parseAction.setMenuBarData(new MenuData(menuPath, IMPORT_EXPORT_GROUP));
		parseAction.setEnabled(true);
		tool.addAction(parseAction);

		DockingAction writeGslAction = new DockingAction(WRITE_GSL, getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				File gslInfile = chooseFile(tool.getToolFrame(), "Select input file",
					GDT_ARCHIVE_DIR, FileDataTypeManager.SUFFIX);
				File gslOutfile =
					chooseFile(tool.getToolFrame(), "Select output file", GSL_ARCHIVE_DIR, "gsl");
				new TaskLauncher(new GSLWriterTask(tool, gslInfile, gslOutfile),
					tool.getToolFrame());
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return context.getContextObject() instanceof ListingActionContext;
			}
		};
		String[] menuPath2 = { ToolConstants.MENU_FILE, "Write GSL Archive..." };
		writeGslAction.setMenuBarData(new MenuData(menuPath2, IMPORT_EXPORT_GROUP));
		writeGslAction.setEnabled(true);
		tool.addAction(writeGslAction);
	}

	private class GSLParserTask extends Task {
		PluginTool myTool;
		File gslArchive;

		public GSLParserTask(PluginTool tool, File gslArchive) {
			super("GSL Archive Parser", true, true, false);
			this.gslArchive = gslArchive;
			this.myTool = tool;
		}

		@Override
		public void run(TaskMonitor monitor) {
			int lineCount = 0;
			try {
				if (gslArchive != null) {
					String gslName = gslArchive.getName();
					String gslNameWithPath = gslArchive.getAbsolutePath();
					monitor.setMessage("Parsing " + gslName);
					FileDataTypeManager dtMgr = FileDataTypeManager.createFileArchive(
						new File(gslNameWithPath + FileDataTypeManager.SUFFIX));
					int id = dtMgr.startTransaction("process archive");
					try {
						addPrimitives(dtMgr);

						BufferedReader reader = new BufferedReader(new FileReader(gslArchive));
						while (reader.readLine() != null) {
							lineCount++;
						}
						reader.close();
						monitor.initialize(lineCount);

						reader = new BufferedReader(new FileReader(gslArchive));
						String line;
						lineCount = 0;
						DataType dt = null;
						while (((line = reader.readLine()) != null) && !monitor.isCancelled()) {
							try {
								dt = parseLine(dtMgr, line);
								if (dt != null) {
									addDataType(dtMgr, dataTypes, dt);
								}
								if (lineCount % 100 == 0) {
									monitor.setProgress(lineCount);
								}
								lineCount++;
							}
							catch (Exception e) {
								Msg.error(this,
									"Error in " + name + " at line " + lineCount + " of " +
										gslArchive.getName() +
										"...possibly an attempt to redefine a Ghidra primitive",
									e);
							}
						}
						reader.close();

					}
					finally {
						dtMgr.endTransaction(id, true);
					}

					monitor.setMessage("Checking for parser errors");
					searchForErrors(dtMgr);

					monitor.setMessage("Writing XML file");
					try {
						DataTypesXmlMgr.writeAsXMLForDebug(dtMgr, gslNameWithPath);
					}
					catch (Exception e) {
						Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
					}

					try {
						dtMgr.save();
					}
					catch (Exception e) {
						Msg.showError(this, myTool.getToolFrame(), "GSL Archive Parser",
							gslNameWithPath + ".gdt already exists - not overwritten", e);
					}
					dtMgr.close();
				}
			}
			catch (Exception e) {
				Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			}
			return;
		}
	}

	private class GSLWriterTask extends Task {
		File gslInfile;
		File gslOutfile;

		public GSLWriterTask(PluginTool tool, File gslInfile, File gslOutfile) {
			super("GSL Archive Writer", true, false, false);
			this.gslInfile = gslInfile;
			this.gslOutfile = gslOutfile;
		}

		@Override
		public void run(TaskMonitor monitor) {
			if (gslInfile != null) {
				DataTypeManager dtMgr = null;
				try {
					dtMgr = FileDataTypeManager.openFileArchive(gslInfile, false);
				}
				catch (Exception e) {
					Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
				}
				if (dtMgr != null) {
					try {
						monitor.setMessage("Writing " + gslOutfile.getName());
						writeAsGsl(gslOutfile, dtMgr, monitor);
					}
					finally {
						dtMgr.close();
					}
				}
			}
			return;
		}
	}

	private DataType parseLine(FileDataTypeManager dtMgr, String line) {
		DataType dt = null;
		int index;
		// "$$" doesn't get parsed correctly, so replace it with "$ $"
		while ((index = line.indexOf("$$")) >= 0) {
			line = line.substring(0, index + 1) + "noname" + line.substring(index + 1);
		}
		while ((index = line.indexOf("//")) >= 0) {
			line = line.substring(0, index) + line.substring(index + 1);
		}

		StringTokenizer tokenizer = new StringTokenizer(line, "$");
		String fieldId = tokenizer.nextToken();
		String complexName = tokenizer.nextToken();

		ComplexName cName = new ComplexName(complexName);
		String myName = cName.getName();

		if ((fieldId.compareToIgnoreCase("STRUCT") == 0) ||
			(fieldId.compareToIgnoreCase("UNION") == 0)) {
			tokenizer.nextToken(); // size
			tokenizer.nextToken(); // alignment
			if (fieldId.compareToIgnoreCase("STRUCT") == 0) {
				dt = new StructureDataType(cName.getCategoryPath(), myName, 0);
			}
			else {
				dt = new UnionDataType(cName.getCategoryPath(), myName);
			}
			addDataType(dtMgr, dataTypes, dt);

			int lastOffset = dt.getLength();
			DataType member;
			while (tokenizer.hasMoreElements()) {
				String fieldName = tokenizer.nextToken();
				String fieldType = tokenizer.nextToken();
				String fieldOffset = tokenizer.nextToken();
				String fieldSize = tokenizer.nextToken();
				String fieldAlign = tokenizer.nextToken();

				int align = valueOf(fieldAlign);
				int fSize = valueOf(fieldSize);
				int fOff = valueOf(fieldOffset);
				ComplexName fType = new ComplexName(fieldType);
				member = fType.getDataType(dtMgr, dataTypes);

				try {
					// If we don't know what this is, make something up
					if ((member == null) || (member.getLength() < 0)) {
						member = genUIData(dtMgr, fType, fOff - dt.getLength());
						fSize = member.getLength();
					}
					// Zero length fields are OK if they're the last field (again we fake the size)
					if (member.getLength() == 0) {
						if (!tokenizer.hasMoreElements()) {
							fType.count = 1;
							member = fType.getDataType(dtMgr, dataTypes);
							fSize = member.getLength();
						}
					}

					if ((dt instanceof Structure) && ((fOff < dt.getLength()) ||
						((fOff >= dt.getLength()) && (fSize < member.getLength())))) {
						if (fOff >= dt.getLength()) {
							lastOffset = dt.getLength();
							((StructureDataType) dt).add(member, member.getLength(),
								"_bit_fields_" + dt.getLength(), "");
						}
						DataTypeComponent dtc = ((StructureDataType) dt).getComponentAt(lastOffset);
						String comment = dtc.getComment();
						comment += " " + fieldName + "(" + fieldSize + ")";
						dtc.setComment(comment);
						if (fSize < member.getLength()) {
							Msg.debug(this, "Dropping bitfield=[" + fieldName + "] type=[" +
								member.getName() + "] in " + myName);
						}
						else {
							Msg.debug(this, "Dropping  element=[" + fieldName + "] type=[" +
								member.getName() + "] in " + myName);
						}
					}
					else {
						// HACKALERT:  Big ol' hack here... (GSL appears to be lying to us)
						if (align > 4) {
							align = 4;
						}
						int mod = (align == 0) ? 0 : dt.getLength() % align;
						DataType modDt = null;
						if (mod != 0) {
							modDt = new ArrayDataType(new ByteDataType(), align - mod, 1);
						}
						if (member.getLength() > 0) {
							lastOffset = dt.getLength();
							if (modDt != null) {
								((CompositeDataTypeImpl) dt).add(modDt, modDt.getLength(),
									"_fill_" + dt.getLength(), ALIGNMENT_TAG);
							}
							((CompositeDataTypeImpl) dt).add(member, member.getLength(), fieldName,
								"");
						}
						else {
							Msg.debug(this, "Dropping mid-structure zero length element=[" +
								fieldName + "] type=[" + member.getName() + "] in " + myName);
						}
					}
				}
				catch (Exception e) {
					Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
				}
			}
		}
		else if (fieldId.compareToIgnoreCase("FUNCTION") == 0) {
			dt = new FunctionDefinitionDataType(cName.getCategoryPath(), cName.getName());
			String retVal = tokenizer.nextToken();
			ComplexName rvName = new ComplexName(retVal);
			DataType rvDt = rvName.getDataType(dtMgr, dataTypes);
			if (rvDt == null) {
				rvDt = genUIData(dtMgr, rvName, 4);
			}
			((FunctionDefinitionDataType) dt).setReturnType(rvDt);
			ArrayList<ParameterDefinition> parameters = new ArrayList<>();
			index = 0;
			while (tokenizer.hasMoreElements()) {
				String fieldName = tokenizer.nextToken();
				String fieldType = tokenizer.nextToken();
				ComplexName fType = new ComplexName(fieldType);
				DataType parameter = fType.getDataType(dtMgr, dataTypes);
				if (parameter == null) {
					parameter = genUIData(dtMgr, fType, 4);
				}
				parameters.add(new ParameterDefinitionImpl(fieldName, parameter, ""));
				index++;
			}
			if (index > 0) {
				ParameterDefinition[] parms = new ParameterDefinition[parameters.size()];
				parameters.toArray(parms);
				((FunctionDefinitionDataType) dt).setArguments(parms);
			}
		}
		else if (fieldId.compareToIgnoreCase("TYPEDEF") == 0) {
			String newName = tokenizer.nextToken();
			try {
				DataType baseType = cName.getDataType(dtMgr, dataTypes);
				if (baseType == null) {
					baseType = genUIData(dtMgr, cName, 4);
				}
				ComplexName cNewName = new ComplexName(newName);
				dt = new TypedefDataType(cNewName.getCategoryPath(), newName, baseType);
			}
			catch (Exception e) {
				Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			}
		}
		else if (fieldId.compareToIgnoreCase("ENUM") == 0) {
			ArrayList<String> fNames = new ArrayList<>();
			ArrayList<String> fValues = new ArrayList<>();
			while (tokenizer.hasMoreElements()) {
				fNames.add(tokenizer.nextToken());
				fValues.add(tokenizer.nextToken());
			}
			dt = new EnumDataType(cName.getCategoryPath(), cName.getName(), fNames.size(), null);
			for (int i = 0; i < fNames.size(); i++) {
				((EnumDataType) dt).add(fNames.get(i), new Long(fValues.get(i)).longValue());
			}
		}
		else if (fieldId.compareToIgnoreCase("SYMBOL") == 0) {

		}
		else {
			Msg.warn(this, "What is this? " + fieldId);
		}
		return dt;
	}

	private void searchForErrors(FileDataTypeManager dtMgr) {
		try {
			Iterator<DataType> dts = dtMgr.getAllDataTypes();
			while (dts.hasNext()) {
				DataType dti = dts.next();
				if (dti.getDisplayName().indexOf("%") >= 0) {
					Msg.warn(this, "Misprocessed data type: " + dti.getDisplayName());
				}
				if (dti instanceof TypeDef) {
					DataType base = ((TypeDef) dti).getBaseDataType();
					if (base instanceof Pointer) {
						base = ((Pointer) base).getDataType();
						if (base.isEquivalent(dataUI)) {
							Msg.warn(this, "Data type (" + dti.getDisplayName() + ") not found.");
						}
					}
				}
			}
		}
		catch (Exception e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}
	}

	public DataType genUIData(FileDataTypeManager dtMgr, ComplexName cName, int len) {
		TypedefDataType dt = new TypedefDataType(cName.getCategoryPath(), cName.getName(),
			new ArrayDataType(new ByteDataType(), len, 1));
		addDataType(dtMgr, dataTypes, dt);
		return dt;
	}

	int valueOf(String intString) {
		return (new Integer(intString)).intValue() / 8;
	}

	private void addPrimitives(FileDataTypeManager dtMgr) {
		addDataType(dtMgr, dataTypes, new TypedefDataType("char", new ByteDataType()));
		addDataType(dtMgr, dataTypes, new TypedefDataType("signed char", new ByteDataType()));
		addDataType(dtMgr, dataTypes, new TypedefDataType("unsigned char", new ByteDataType()));

		addDataType(dtMgr, dataTypes, new TypedefDataType("short", new WordDataType()));
		addDataType(dtMgr, dataTypes, new TypedefDataType("short int", new WordDataType()));
		addDataType(dtMgr, dataTypes, new TypedefDataType("short signed int", new WordDataType()));
		addDataType(dtMgr, dataTypes,
			new TypedefDataType("short unsigned int", new WordDataType()));

		addDataType(dtMgr, dataTypes, new TypedefDataType("int", new DWordDataType()));
		addDataType(dtMgr, dataTypes, new TypedefDataType("long", new DWordDataType()));
		addDataType(dtMgr, dataTypes, new TypedefDataType("long int", new DWordDataType()));
		addDataType(dtMgr, dataTypes, new TypedefDataType("signed int", new DWordDataType()));
		addDataType(dtMgr, dataTypes, new TypedefDataType("unsigned int", new DWordDataType()));
		addDataType(dtMgr, dataTypes, new TypedefDataType("long signed int", new DWordDataType()));
		addDataType(dtMgr, dataTypes,
			new TypedefDataType("long unsigned int", new DWordDataType()));

		addDataType(dtMgr, dataTypes, new TypedefDataType("long long int", new QWordDataType()));
		addDataType(dtMgr, dataTypes,
			new TypedefDataType("long long signed int", new QWordDataType()));
		addDataType(dtMgr, dataTypes,
			new TypedefDataType("long long unsigned int", new QWordDataType()));

		addDataType(dtMgr, dataTypes, new TypedefDataType("void", new VoidDataType()));
		dataUI = new TypedefDataType("U/I", new DWordDataType());
		addDataType(dtMgr, dataTypes, dataUI);
	}

	private void addDataType(FileDataTypeManager dtMgr, Hashtable<String, DataType> myDataTypes,
			DataType dt) {
		DataType type = dtMgr.addDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER);
		myDataTypes.put(type.getCategoryPath() + type.getName(), type);
	}

	private File chooseFile(Component parent, String title, String propertyName,
			final String fileType) {
		if (fileChooser == null) {
			fileChooser = new GhidraFileChooser(parent);
		}
		fileChooser.setFileFilter(new ExtensionFileFilter(fileType,
			fileType.toUpperCase() + " files (." + fileType + ")"));
		fileChooser.setTitle(title);

		// start the browsing in the user's preferred directory
		//
		File directory =
			new File(Preferences.getProperty(propertyName, System.getProperty("user.home"), true));
		fileChooser.setCurrentDirectory(directory);
		fileChooser.setSelectedFile(directory);

		File file = fileChooser.getSelectedFile();
		if (file != null) {
			// record where we last exported a file from to the user's preferences
			Preferences.setProperty(propertyName, file.getAbsolutePath());
		}

		return file;
	}

	final static String NO_NAMESPACE = "/";
	final int SIZE_X = 8;
	final int ALIGNMENT = 32;

	private void writeAsGsl(File file, DataTypeManager dtMgr, TaskMonitor monitor) {
		String out = "";
		int count = 0;
		try {
			FileOutputStream stream = new FileOutputStream(file);
			Iterator<DataType> it = dtMgr.getAllDataTypes();
			while (it.hasNext()) {
				DataType dt = it.next();
				out = "";
				if (dt instanceof Composite) {
					out = writeComposite(stream, dt);
				}
				else if (dt instanceof TypeDef) {
					out = writeTypeDef(stream, (TypeDef) dt);
				}
				else if (dt instanceof FunctionDefinition) {
					out = writeFunctionDefinition(stream, (FunctionDefinition) dt);
				}
				else if (dt instanceof Enum) {
					out = writeEnum(stream, (Enum) dt);
				}
				else {
					Msg.debug(this, "Something went wrong while printing GSL output...");
				}
				if (out != "") {
					stream.write(out.getBytes());
				}
				if (count % 100 == 0) {
					monitor.setProgress(count);
				}
				count++;
			}
			stream.close();
		}
		catch (Exception e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}
	}

	private String writeComposite(FileOutputStream stream, DataType dt) {
		String out;
		DataTypeComponent[] components;

		out = (dt instanceof Structure) ? "STRUCT$" : "UNION$";
		components = ((Composite) dt).getComponents();
		out += new NameComplex(dt).getGSLName() + "$";
		out += SIZE_X * dt.getLength() + "$";
		out += ALIGNMENT;
		for (DataTypeComponent component : components) {
			String comment = component.getComment();
			if ((comment != null) && (comment.compareTo(ALIGNMENT_TAG) != 0)) {
				NameComplex cComp = new NameComplex(component.getDataType());
				out += "$";
				out += component.getFieldName() + "$";
				out += cComp.getGSLName() + "$";
				out += SIZE_X * component.getOffset() + "$";
				out += SIZE_X * component.getLength() + "$";
				if (component.getDataType() instanceof Composite) {
					out += ALIGNMENT;
				}
				else {
					out += SIZE_X * cComp.getBaseTypeSize();
				}
			}
		}
		out += "\n";
		return out;
	}

	private String writeTypeDef(FileOutputStream stream, TypeDef def) {
		DataType dt = def.getDataType();

		String out = "TYPEDEF$";
		out += new NameComplex(dt).getGSLName() + "$";
		out += new NameComplex(def).getGSLName() + "\n";
		return out;
	}

	private String writeEnum(FileOutputStream stream, Enum enuum) {
		String out = "ENUM$";
		String[] names = enuum.getNames();
		long[] values = enuum.getValues();

		out += new NameComplex(enuum).getGSLName();
		for (int i = 0; i < names.length; i++) {
			out += "$";
			out += names[i] + "$";
			out += values[i];
		}
		out += "\n";
		return out;
	}

	private String writeFunctionDefinition(FileOutputStream stream, FunctionDefinition fn) {
		String out = "FUNCTION$";
		ParameterDefinition[] parameters = fn.getArguments();
		DataType ret = fn.getReturnType();

		out += new NameComplex(fn).getGSLName() + "$";
		out += new NameComplex(ret).getGSLName();
		for (ParameterDefinition parameter : parameters) {
			NameComplex cParm = new NameComplex(parameter.getDataType());
			out += "$";
			String pName = parameter.getName();
			out += ((pName.compareToIgnoreCase(" ") == 0) ? "" : pName);
			out += "$";
			out += cParm.getGSLName();
		}
		out += "\n";
		return out;
	}

	public class NameComplex {

		DataType dt;
		String myName;
		String dtNamespace;
		int baseTypeSize;

		public NameComplex(DataType dt) {
			this.dt = dt;
			dtNamespace = dt.getCategoryPath().getPath();

			DataType base = dt;
			boolean shouldDescend = false;
			myName = "";
			if (dt instanceof Pointer) {
				myName = "Pointer%";
				base = ((Pointer) dt).getDataType();
				shouldDescend = true;
			}
			else if (dt instanceof Array) {
				Array array = (Array) dt;
				myName =
					"Array%" + array.getNumElements() + "%" + (SIZE_X * array.getLength() + "%");
				base = array.getDataType();
				shouldDescend = true;
			}

			if (shouldDescend) {
				NameComplex cName = new NameComplex(base);
				myName += cName.getGSLName();
				if (dt instanceof Pointer) {
					baseTypeSize = dt.getLength();
				}
				else {
					baseTypeSize = cName.getBaseTypeSize();
				}
			}
			else {
				if (dtNamespace.compareToIgnoreCase(NO_NAMESPACE) != 0) {
					myName += dtNamespace + ":";
				}
				myName += dt.getName();
				baseTypeSize = dt.getLength();
			}
		}

		public String getGSLName() {
			return myName;
		}

		public int getBaseTypeSize() {
			return baseTypeSize;
		}
	}
}
