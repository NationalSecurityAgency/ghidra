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
package agent.dbgmodel.dbgmodel.datamodel;

import com.sun.jna.WString;
import com.sun.jna.platform.win32.Variant.VARIANT.ByReference;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgmodel.dbgmodel.UnknownEx;
import agent.dbgmodel.dbgmodel.concept.DataModelConcept;
import agent.dbgmodel.dbgmodel.datamodel.script.DataModelScriptManager;
import agent.dbgmodel.dbgmodel.debughost.*;
import agent.dbgmodel.dbgmodel.main.KeyStore;
import agent.dbgmodel.dbgmodel.main.ModelObject;
import agent.dbgmodel.jna.dbgmodel.DbgModelNative.LOCATION;
import agent.dbgmodel.jna.dbgmodel.DbgModelNative.ModelObjectKind;

/**
 * A wrapper for {@code IDataModelManager1} and its newer variants.
 */
public interface DataModelManager1 extends UnknownEx {

	void close();

	ModelObject createNoValue();

	ModelObject createErrorObject(HRESULT hrError, WString pwszMessage);

	ModelObject createTypedObject(DebugHostContext context, LOCATION objectLocation,
			DebugHostType1 objectType);

	ModelObject createTypedObjectReference(DebugHostContext context, LOCATION objectLocation,
			DebugHostType1 objectType);

	ModelObject createSyntheticObject(DebugHostContext context);

	ModelObject createDataModelObject(DataModelConcept dataModel);

	ModelObject createIntrinsicObject(ModelObjectKind objectKind, ByReference intrinsicData);

	ModelObject createTypedIntrinsicObject(ByReference intrinsicData, DebugHostType1 type);

	ModelObject getModelForTypeSignature(DebugHostTypeSignature typeSignature);

	ModelObject getModelForType(DebugHostType1 type);

	void registerModelForTypeSignature(DebugHostTypeSignature typeSignature,
			ModelObject dataModel);

	void unregisterModelForTypeSignature(ModelObject dataModel,
			DebugHostTypeSignature typeSignature);

	void registerExtensionForTypeSignature(DebugHostTypeSignature typeSignature,
			ModelObject dataModel);

	void unregisterExtensionForTypeSignature(ModelObject dataModel,
			DebugHostTypeSignature typeSignature);

	KeyStore createMetadataStore(KeyStore parentStore);

	ModelObject getRootNamespace();

	void registerNamedModel(WString modelName, ModelObject modelObject);

	void unregisterNamedModel(WString modelName);

	ModelObject acquireNamedModel(WString modelName);

	DataModelScriptManager asScriptManager();

}
