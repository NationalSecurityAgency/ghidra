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
package ghidra.app.util.demangler.swift;

import ghidra.app.util.demangler.swift.nodes.SwiftNode;

/**
 * Kinds of Swift demangling {@link SwiftNode}s
 * 
 * @see <a href="https://github.com/apple/swift/blob/main/include/swift/Demangling/DemangleNodes.def">DemangleNodes.def</a> 
 */
public enum SwiftDemangledNodeKind {
	//@formatter:off
	
	Allocator,
	AnonymousDescriptor,
	ArgumentTuple,
	BoundGenericStructure,
	BuiltinTypeName,
	Class,
	Constructor,
	Deallocator,
	DefaultArgumentInitializer,
	DependentGenericParamType,
	DependentGenericType,
	Destructor,
	DispatchThunk,
	Enum,
	Extension,
	FirstElementMarker,
	Function,
	FunctionType,
	GenericSpecialization,
	Getter,
	Global,
	GlobalVariableOnceDeclList,
	GlobalVariableOnceFunction,
	Identifier,
	InfixOperator,
	Initializer,
	InOut,
	LabelList,
	LazyProtocolWitnessTableAccessor,
	LocalDeclName,
	MergedFunction,
	ModifyAccessor,
	Module,
	ModuleDescriptor,
	NominalTypeDescriptor,
	Number,
	ObjCAttribute,
	OutlinedConsume,
	OutlinedCopy,
	Owned,
	PrivateDeclName,
	Protocol,
	ProtocolConformance,
	ProtocolConformanceDescriptor,
	ProtocolDescriptor,
	ProtocolWitness,
	ReflectionMetadataBuiltinDescriptor,
	ReflectionMetadataFieldDescriptor,
	ReturnType,
	Setter,
	Static,
	Structure,
	Subscript,
	Suffix,
	Tuple,
	TupleElement,
	TupleElementName,
	Type,
	TypeAlias,
	TypeList,
	TypeMetadataAccessFunction,
	UnsafeMutableAddressor,
	Unsupported,
	Variable;
	
	//@formatter:on
}
