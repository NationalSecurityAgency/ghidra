import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.data.rtti.gcc.builder.AbstractTypeInfoProgramBuilder;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.gcc.CreateVtableBackgroundCmd;
import ghidra.app.cmd.data.rtti.gcc.GccUtils;
import ghidra.app.cmd.data.rtti.TypeInfo;
import ghidra.app.cmd.data.rtti.gcc.VtableModel;
import ghidra.app.cmd.data.rtti.gcc.VttModel;
import ghidra.app.cmd.data.rtti.gcc.typeinfo.TypeInfoModel;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.Structure;

import javax.lang.model.element.Modifier;

import com.squareup.javapoet.ArrayTypeName;
import com.squareup.javapoet.CodeBlock;
import com.squareup.javapoet.FieldSpec;
import com.squareup.javapoet.JavaFile;
import com.squareup.javapoet.MethodSpec;
import com.squareup.javapoet.ParameterizedTypeName;
import com.squareup.javapoet.TypeName;
import com.squareup.javapoet.TypeSpec;

import static ghidra.app.cmd.data.rtti.gcc.factory.TypeInfoFactory.getTypeInfo;
import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.getAbsoluteAddress;
import static ghidra.program.model.data.DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA;

import java.io.File;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class GccTypeInfoTestBuilder extends GhidraScript {

    private static final String MAP_OF_ENTRIES = "Map.ofEntries(\n";
    private static final String TYPE_MAP_FIELD = "typeMap";
    private static final String NAME_MAP_FIELD = "nameMap";
    private static final String VTABLE_MAP_FIELD = "vtableMap";
    private static final String VTT_MAP_FIELD = "vttMap";
    private static final String RELOCATION_MAP_FIELD = "relocationMap";
    private static final String FUNCTION_OFFSETS_FIELD = "functionOffsets";
    private static final String RETURN_STRING_FIELD = "returnString";
    private static final String FUNCTION_DESCRIPTORS_FIELD = "fDescriptors";

    private Map<TypeInfo, byte[]> tiMap = new LinkedHashMap<>();
    private Map<String, Address> nameMap = new LinkedHashMap<>();
    private Map<VtableModel, byte[]> vtableMap = new LinkedHashMap<>();
    private Map<VttModel, byte[]> vttMap = new LinkedHashMap<>();
    private Set<Function> functionSet = new LinkedHashSet<>();

    private static final TypeName MAP_TYPE =
        ParameterizedTypeName.get(Map.class, Long.class, String.class);
    private static final TypeName ARRAY_TYPE = ArrayTypeName.of(Long.class);
    private static final TypeName STRING_TYPE = TypeName.get(String.class);

    private static final String VTABLE_PREFIX = "_ZTV";
    private static final String CREATE_MEMORY = "createMemory($S, $S, $L)";
    private static final String PURE_VIRTUAL = "__cxa_pure_virtual";

    @Override
    public void run() throws Exception {
        populateMaps();
        buildClass();
    }

    private void buildClass() throws Exception {
        File file = askDirectory("Select Directory", "Ok");
        String name = askString("Class Name", "Enter Class Name");
        TypeSpec tester = TypeSpec.classBuilder(name)
            .addModifiers(Modifier.PUBLIC)
            .superclass(AbstractTypeInfoProgramBuilder.class)
            .addField(getTypeMapField())
            .addField(getNameMapField())
            .addField(getVtableMapField())
            .addField(getVttMapField())
            .addField(getRelocationMapField())
            .addField(getFunctionArrayField())
            .addField(getReturnFunctionField())
            .addField(getFunctionDescriptorField())
            .addMethod(makeConstructor())
            .addMethod(makeGetter("getTypeInfoMap", TYPE_MAP_FIELD, MAP_TYPE))
            .addMethod(makeGetter("getTypeNameMap", NAME_MAP_FIELD, MAP_TYPE))
            .addMethod(makeGetter("getVtableMap", VTABLE_MAP_FIELD, MAP_TYPE))
            .addMethod(makeGetter("getVttMap", VTT_MAP_FIELD, MAP_TYPE))
            .addMethod(makeGetter("getRelocationMap", RELOCATION_MAP_FIELD, MAP_TYPE))
            .addMethod(makeGetter("getFunctionOffsets", FUNCTION_OFFSETS_FIELD, ARRAY_TYPE))
            .addMethod(makeGetter("getReturnInstruction", RETURN_STRING_FIELD, STRING_TYPE))
            .addMethod(
                makeGetter("getFunctionDescriptors", FUNCTION_DESCRIPTORS_FIELD, STRING_TYPE))
            .addMethod(makeSetupMemory())
            .build();

        JavaFile.builder("ghidra.app.cmd.data.rtti.gcc.builder", tester)
            .skipJavaLangImports(true)
            .indent("    ")
            .build().writeTo(file);
    }

    private FieldSpec getTypeMapField() throws Exception {
        return FieldSpec.builder(MAP_TYPE, TYPE_MAP_FIELD)
            .addModifiers(Modifier.PRIVATE, Modifier.STATIC, Modifier.FINAL)
            .initializer(getTypeMapInitializer()).build();
    }

    private FieldSpec getNameMapField() throws Exception {
        return FieldSpec.builder(MAP_TYPE, NAME_MAP_FIELD)
            .addModifiers(Modifier.PRIVATE, Modifier.STATIC, Modifier.FINAL)
            .initializer(getNameMapInitializer()).build();
    }

    private FieldSpec getVtableMapField() throws Exception {
        return FieldSpec.builder(MAP_TYPE, VTABLE_MAP_FIELD)
            .addModifiers(Modifier.PRIVATE, Modifier.STATIC, Modifier.FINAL)
            .initializer(getVtableMapInitializer()).build();
    }

    private FieldSpec getVttMapField() throws Exception {
        return FieldSpec.builder(MAP_TYPE, VTT_MAP_FIELD)
            .addModifiers(Modifier.PRIVATE, Modifier.STATIC, Modifier.FINAL)
            .initializer(getVttMapInitializer()).build();
    }

    private FieldSpec getRelocationMapField() throws Exception {
        return FieldSpec.builder(MAP_TYPE, RELOCATION_MAP_FIELD)
            .addModifiers(Modifier.PRIVATE, Modifier.STATIC, Modifier.FINAL)
            .initializer(getRelocationMapInitializer()).build();
    }

    private FieldSpec getFunctionArrayField() throws Exception {
        return FieldSpec.builder(ARRAY_TYPE, FUNCTION_OFFSETS_FIELD)
            .addModifiers(Modifier.PRIVATE, Modifier.STATIC, Modifier.FINAL)
            .initializer(getFunctionArrayInitializer()).build();
    }

    private FieldSpec getReturnFunctionField() throws Exception {
        for (Symbol symbol : currentProgram.getSymbolTable().getSymbols("g_foo")) {
            Function function = getFunctionAt(symbol.getAddress());
            return FieldSpec.builder(String.class, RETURN_STRING_FIELD)
                .addModifiers(Modifier.PRIVATE, Modifier.STATIC, Modifier.FINAL)
                .initializer("$S", byteArrayToHex(getBytes(
                    function.getEntryPoint(), (int) function.getBody().getNumAddresses())))
                .build();
        }
        return null;
    }

    private FieldSpec getFunctionDescriptorField() throws Exception {
        FieldSpec.Builder builder = FieldSpec.builder(STRING_TYPE, FUNCTION_DESCRIPTORS_FIELD)
            .addModifiers(Modifier.PRIVATE, Modifier.STATIC, Modifier.FINAL);
        if (GnuUtils.hasFunctionDescriptors(currentProgram)) {
            MemoryBlock block = getFunctionDescriptorBlock();
            byte[] bytes = new byte[(int) block.getSize()];
            block.getBytes(block.getStart(), bytes);
            return builder.initializer("$S", byteArrayToHex(bytes)).build();
        } return builder.initializer("$S", "").build();
    }

    private MemoryBlock getFunctionDescriptorBlock() {
        return currentProgram.getMemory().getBlock(".opd");
    }

    private CodeBlock getTypeMapInitializer() throws Exception {
        List<CodeBlock> blocks = new LinkedList<>();
        for (TypeInfo type : tiMap.keySet()) {
            blocks.add(
                CodeBlock.builder().add(
                    "getEntry(0x$LL, $S)",
                    type.getAddress().toString(), byteArrayToHex(tiMap.get(type))
                    ).build());
        }
        return CodeBlock.builder()
            .add(MAP_OF_ENTRIES)
            .indent()
            .add(CodeBlock.join(blocks, ",\n"))
            .unindent()
            .add("\n)")
            .build();
    }

    private CodeBlock getNameMapInitializer() throws Exception {
        List<CodeBlock> blocks = new LinkedList<>();
        for (String name : nameMap.keySet()) {
            blocks.add(
                CodeBlock.builder().add(
                    "getEntry(0x$LL, $S)",
                    nameMap.get(name), name
                ).build());
        }
        return CodeBlock.builder()
            .add(MAP_OF_ENTRIES)
            .indent()
            .add(CodeBlock.join(blocks, ",\n"))
            .unindent()
            .add("\n)")
            .build();
    }

    private CodeBlock getVtableMapInitializer() throws Exception {
        List<CodeBlock> blocks = new LinkedList<>();
        for (VtableModel vtable : vtableMap.keySet()) {
            blocks.add(
                CodeBlock.builder().add(
                    "getEntry(0x$LL, $S)",
                    vtable.getAddress().toString(), byteArrayToHex(vtableMap.get(vtable))
                    ).build());
        }
        return CodeBlock.builder()
            .add(MAP_OF_ENTRIES)
            .indent()
            .add(CodeBlock.join(blocks, ",\n"))
            .unindent()
            .add("\n)")
            .build();
    }

    private CodeBlock getVttMapInitializer() throws Exception {
        List<CodeBlock> blocks = new LinkedList<>();
        for (VttModel vtt : vttMap.keySet()) {
            blocks.add(
                CodeBlock.builder().add(
                    "getEntry(0x$LL, $S)",
                    vtt.getAddress().toString(), byteArrayToHex(vttMap.get(vtt))
                    ).build());
        }
        return CodeBlock.builder()
            .add(MAP_OF_ENTRIES)
            .indent()
            .add(CodeBlock.join(blocks, ",\n"))
            .unindent()
            .add("\n)")
            .build();
    }

    private static boolean validRelocationSymbol(String symbolName) {
        if (symbolName == null) {
            return false;
        } if (symbolName.equals(PURE_VIRTUAL)) {
            return true;
        } if (symbolName.contains(VTABLE_PREFIX) && symbolName.contains(TypeInfoModel.STRUCTURE_NAME)) {
            return true;
        } return false;
    }

    private CodeBlock getRelocationMapInitializer() throws Exception {
        Iterator<Relocation> relocations = currentProgram.getRelocationTable().getRelocations();
        List<CodeBlock> blocks = new LinkedList<>();
        while (relocations.hasNext()) {
            Relocation relocation = relocations.next();
            if (validRelocationSymbol(relocation.getSymbolName())) {
                blocks.add(
                    CodeBlock.builder().add(
                        "getEntry(0x$LL, $S)",
                        relocation.getAddress().toString(), relocation.getSymbolName()
                        ).build());
            }
        }
        return CodeBlock.builder()
            .add(MAP_OF_ENTRIES)
            .indent()
            .add(CodeBlock.join(blocks, ",\n"))
            .unindent()
            .add("\n)")
            .build();
    }

    private CodeBlock getFunctionArrayInitializer() throws Exception {
        List<CodeBlock> blocks = new LinkedList<>();
        for (Function function : functionSet) {
            blocks.add(
                CodeBlock.builder().add(
                    "0x$LL",
                    function.getEntryPoint().toString()).build());
        }
        return CodeBlock.builder()
            .add("new Long[]{\n")
            .indent()
            .add(CodeBlock.join(blocks, ",\n"))
            .add("\n}")
            .build();
    }

    private MethodSpec makeGetter(String methodName, String field, TypeName type) {
        return MethodSpec.methodBuilder(methodName)
        .addAnnotation(Override.class)
        .addModifiers(Modifier.PROTECTED)
        .returns(type)
        .addStatement("return $L", field)
        .build();
    }

    private MethodSpec makeConstructor() {
        return MethodSpec.constructorBuilder()
            .addModifiers(Modifier.PUBLIC)
            .addException(Exception.class)
            .addStatement(
                "super($S, $S)",
                currentProgram.getLanguage().getLanguageID().toString(),
                currentProgram.getCompilerSpec().getCompilerSpecID().toString()
            )
            .build();
    }

    private MethodSpec makeSetupMemory() {
        MemoryBlock codeBlock = getFunctionBlock();
        MemoryBlock dataBlock = getDataBlock();
        MethodSpec.Builder builder = MethodSpec.methodBuilder("setupMemory")
            .addAnnotation(Override.class)
            .addModifiers(Modifier.PROTECTED)
            .addStatement(
                CREATE_MEMORY,
                codeBlock.getName(),
                codeBlock.getStart().toString(),
                codeBlock.getSize())
            .addStatement(
                CREATE_MEMORY,
                dataBlock.getName(),
                dataBlock.getStart().toString(),
                dataBlock.getSize());
        if (GnuUtils.hasFunctionDescriptors(currentProgram)) {
            MemoryBlock block = getFunctionDescriptorBlock();
            builder = builder.addStatement(
                CREATE_MEMORY,
                block.getName(),
                block.getStart().toString(),
                block.getSize()
            );
        }
        return builder.build();
    }

    private MemoryBlock getFunctionBlock() {
        for (Function function : functionSet) {
            return getMemoryBlock(function.getEntryPoint());
        }
        return null;
    }

    private MemoryBlock getDataBlock() {
        for (TypeInfo type : tiMap.keySet()) {
            return getMemoryBlock(type.getAddress());
        }
        return null;
    }

    private void populateMaps() throws Exception {
        int pointerSize = currentProgram.getDefaultPointerSize();
        SymbolTable table = currentProgram.getSymbolTable();
        Listing listing = currentProgram.getListing();
        Memory mem = currentProgram.getMemory();
        for (Symbol symbol : table.getSymbols(TypeInfo.SYMBOL_NAME)) {
            TypeInfo type = getTypeInfo(currentProgram, symbol.getAddress());
            try {
                if (type == null) {
                    println("TypeInfo at "+symbol.getAddress().toString()+" is null");
                    continue;
                }
                type.validate();
            } catch (InvalidDataTypeException e) {
                printerr("TypeInfo at "+symbol.getAddress().toString()+" is invalid");
                continue;
            }
            DataType dt = type.getDataType();
            Data data = DataUtilities.createData(
                currentProgram, type.getAddress(), dt,
                dt.getLength(), false, CLEAR_ALL_CONFLICT_DATA);
            if (data.isStructure() && ((Structure) data.getDataType()).hasFlexibleArrayComponent()) {
                MemoryBufferImpl buf = new MemoryBufferImpl(
                    mem, data.getAddress());
                Data flexData = listing.getDataAt(data.getAddress().add(data.getLength()));
                int length = data.getLength();
                if (flexData != null) {
                    length += flexData.getLength();
                }
                byte[] bytes = new byte[length];
                buf.getBytes(bytes, 0);
                tiMap.put(type, bytes);
            } else {
                tiMap.put(type, data.getBytes());
            }
            Address nameAddress = getAbsoluteAddress(
                currentProgram, symbol.getAddress().add(pointerSize));
            nameMap.put(type.getTypeName(), nameAddress);

            if (type instanceof ClassTypeInfo) {
                ClassTypeInfo classType = (ClassTypeInfo) type;
                VtableModel vtable = (VtableModel) classType.getVtable();
                try {
                    vtable.validate();
                } catch (InvalidDataTypeException e) {
                    if (!table.getSymbols(VtableModel.SYMBOL_NAME, classType.getGhidraClass()).isEmpty()) {
                        printerr(type.getNamespace().getName(true)+"'s vtable is invalid");
                    }
                    continue;
                }
                CreateVtableBackgroundCmd cmd = new CreateVtableBackgroundCmd(vtable);
                cmd.applyTo(currentProgram);
                MemoryBufferImpl buf = new MemoryBufferImpl(
                    mem, vtable.getAddress());
                byte[] bytes = new byte[vtable.getLength()];
                buf.getBytes(bytes, 0);
                vtableMap.put(vtable, bytes);
                for (Function[] functionTable : vtable.getFunctionTables()) {
                    for (Function function : functionTable) {
                        if (function != null) {
                            functionSet.add(function);
                        }        
                    }
                }
            }
        }
        for (Symbol symbol : table.getSymbols(VttModel.SYMBOL_NAME)) {
            VttModel vtt = new VttModel(currentProgram, symbol.getAddress());
            if (!vtt.isValid()) {
                printerr(symbol.getParentNamespace().getName()+"'s vtt is invalid");
                continue;
            }
            DataType dt = vtt.getDataType();
            Data data = DataUtilities.createData(
                currentProgram, vtt.getAddress(), dt,
                dt.getLength(), false, CLEAR_ALL_CONFLICT_DATA);
            vttMap.put(vtt, data.getBytes());
        }
    }

    public static String byteArrayToHex(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for(byte b: a)
           sb.append(String.format("%02x", b));
        return sb.toString();
     }
}
