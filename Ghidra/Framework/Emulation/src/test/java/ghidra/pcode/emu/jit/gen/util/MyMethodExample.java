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
package ghidra.pcode.emu.jit.gen.util;

import static java.lang.classfile.ClassFile.ACC_PUBLIC;
import static org.junit.Assert.assertEquals;

import java.lang.classfile.ClassFile;
import java.lang.constant.ClassDesc;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodHandles.Lookup;
import java.lang.reflect.InvocationTargetException;

import org.junit.Test;

import ghidra.pcode.emu.jit.gen.util.Methods.*;
import ghidra.pcode.emu.jit.gen.util.Types.TInt;
import ghidra.pcode.emu.jit.gen.util.Types.TRef;

public class MyMethodExample {
	interface MyIf { // @start region="MyIf"
		int myMethod(int a, String b);
	} // @end region="MyIf"

	@Test
	public void testExample() {
		generateClass();
	}

	<THIS extends MyIf> void generateClass() {
		TRef<Object> typeObject = Types.refOf(Object.class); // @start region="gen"
		Lookup lookup = MethodHandles.lookup();
		String myPackage = lookup.lookupClass().getPackageName();
		TRef<MyIf> typeMyIf = Types.refOf(MyIf.class);
		TRef<THIS> typeThis = Types.refExtends(typeMyIf, ClassDesc.of(myPackage, "GeneratedMyIf"));
		byte[] classbytes = ClassFile.of().build(typeThis.classDesc(), clb -> {
			clb.withFlags(ACC_PUBLIC);
			clb.withSuperclass(typeObject.classDesc());
			clb.withInterfaceSymbols(typeMyIf.classDesc());

			var mdescInit = MthDesc.returns(Types.T_VOID).build();
			Emitter.instanceWithBody(clb, typeThis, "<init>", mdescInit, ACC_PUBLIC, mb -> {
				var p = new Object() {
					Local<TRef<THIS>> this_;
				};
				var spec = mb.startSpec()
						.param(Def::done, typeThis, t -> p.this_ = t);
				return spec.em()
						.emit(Op::aload, p.this_)
						.emit(Op::invokespecial, typeObject, "<init>", mdescInit, false)
						.step(Inv::takeObjRef)
						.step(Inv::retVoid)
						.emit(Op::return_, spec.ret());
			});

			var mdescMyMethod = MthDesc.deriveInst(MyIf::myMethod)
					.check(MthDesc::returns, Types.T_INT)
					.check(MthDesc::param, Types.T_INT)
					.check(MthDesc::param, Types.refOf(String.class))
					.check(MthDesc::build);
			Emitter.instanceWithBody(clb, typeThis, "myMethod", mdescMyMethod, ACC_PUBLIC, mb -> {
				var p = new Object() {
					Local<TRef<THIS>> this_;
					Local<TInt> a;
					Local<TRef<String>> b;
				};
				var spec = mb.startSpec()
						.param(Def::param, Types.refOf(String.class), "b", b -> p.b = b)
						.param(Def::param, Types.T_INT, "a", a -> p.a = a)
						.param(Def::done, typeThis, t -> p.this_ = t);
				return spec.em()
						.emit(Op::iload, p.a)
						.emit(Op::ldc__i, 10)
						.emit(Op::imul)
						.emit(Op::ireturn, spec.ret());
			});
		}); // @end region=gen
		try {
			Lookup clsLookup = MethodHandles.lookup().defineHiddenClass(classbytes, true);
			@SuppressWarnings("unchecked")
			var cls = (Class<? extends MyIf>) clsLookup.lookupClass();
			MyIf generated = cls.getConstructor().newInstance();

			assertEquals(50, generated.myMethod(5, "Hello"));
		}
		catch (IllegalAccessException | InstantiationException | IllegalArgumentException
				| InvocationTargetException | NoSuchMethodException e) {
			throw new AssertionError(e);
		}
	}
}
