/* ###
 * IP: BinCraft
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
#![allow(dead_code)] // TODO: deal with flex and bison, then strip this
use filetime::FileTime;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const DECOMPILER_SOURCE_BASE_CXX: &[&str] = &[
    "space.cc",
    "float.cc",
    "address.cc",
    "pcoderaw.cc",
    "translate.cc",
    "opcodes.cc",
    "globalcontext.cc",
    "capability.cc",
    "architecture.cc",
    "options.cc",
    "graph.cc",
    "cover.cc",
    "block.cc",
    "cast.cc",
    "typeop.cc",
    "database.cc",
    "cpool.cc",
    "comment.cc",
    "stringmanage.cc",
    "fspec.cc",
    "action.cc",
    "loadimage.cc",
    "varnode.cc",
    "op.cc",
    "type.cc",
    "variable.cc",
    "varmap.cc",
    "jumptable.cc",
    "emulate.cc",
    "emulateutil.cc",
    "flow.cc",
    "userop.cc",
    "funcdata.cc",
    "funcdata_block.cc",
    "funcdata_varnode.cc",
    "funcdata_op.cc",
    "pcodeinject.cc",
    "heritage.cc",
    "prefersplit.cc",
    "rangeutil.cc",
    "ruleaction.cc",
    "subflow.cc",
    "transform.cc",
    "blockaction.cc",
    "merge.cc",
    "double.cc",
    "coreaction.cc",
    "condexe.cc",
    "override.cc",
    "dynamic.cc",
    "crc32.cc",
    "prettyprint.cc",
    "printlanguage.cc",
    "printc.cc",
    "printjava.cc",
    "memstate.cc",
    "opbehavior.cc",
    "paramid.cc",
    "ghidra_arch.cc",
    "inject_ghidra.cc",
    "ghidra_translate.cc",
    "loadimage_ghidra.cc",
    "typegrp_ghidra.cc",
    "database_ghidra.cc",
    "ghidra_context.cc",
    "cpool_ghidra.cc",
    "ghidra_process.cc",
    "comment_ghidra.cc",
    "string_ghidra.cc",
    "xml.cc",
];

const DECOMPILER_YACC: &[&'static str] = &["xml.y", "grammar.y"];
const SLEIGH_YACC: &[&'static str] = &["slghparse.y", "pcodeparse.y", "xml.y"];
const SLEIGH_FLEX: &[&'static str] = &["slghscan.l"];

const CLI_CXX: &[&'static str] = &[
    "bfd_arch.cc",
    "loadimage_bfd.cc",
    "sleigh_arch.cc",
    "filemanage.cc",
    "sleigh.cc",
    "sleighbase.cc",
    "context.cc",
    "slghsymbol.cc",
    "semantics.cc",
    "slghpatexpress.cc",
    "slghpattern.cc",
    "inject_sleigh.cc",
    "pcodeparse.cc",
    "slghparse.cc",
    "slghscan.cc",
    "pcodecompile.cc",
    "libdecomp.cc",
    "consolemain.cc",
    "ifaceterm.cc",
    "interface.cc",
    "ifacedecomp.cc",
    "grammar.cc",
    "callgraph.cc",
];

struct CompileOptions {
    sources: Vec<PathBuf>,
    objects: Vec<PathBuf>,
    includes: Vec<PathBuf>,
}

fn output_path(input: &Path, out_extension: &str) -> PathBuf {
    let outdir = env::var("OUT_DIR").unwrap();

    let path = Path::new(&outdir).join(input);
    let mut path = path;
    path.set_extension(out_extension);
    path.to_path_buf()
}

fn needs_recompile(source: &Path, path: &Path) -> bool {
    let metadata = match fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return true,
    };
    let object_mtime = FileTime::from_last_modification_time(&metadata);

    let metadata =
        fs::metadata(source).unwrap_or_else(|_| panic!("source code {:?} not found", source));
    let source_mtime = FileTime::from_last_modification_time(&metadata);

    source_mtime > object_mtime
}

fn run_lex(input: &Path) -> PathBuf {
    let output = output_path(input, "cc");
    if needs_recompile(input, &output) {
        Command::new("flex")
            .args(&["-o", output.to_str().unwrap(), input.to_str().unwrap()])
            .output()
            .expect(&format!(
                "unable generate {} with flex",
                output.to_str().unwrap()
            ));
    }
    output
}

fn run_bison(input: &Path, qualify_vars: bool, gen_header: bool) -> (PathBuf, PathBuf) {
    let cc_file = output_path(input, "cc");
    let header_file = output_path(input, "hh");

    let header_arg = format!("--defines={}", header_file.to_str().unwrap());

    let mut args = vec!["-o", cc_file.to_str().unwrap()];
    if qualify_vars {
        args.push("-p");
        args.push(input.file_name().unwrap().to_str().unwrap());
    }
    if gen_header {
        args.push(&header_arg);
    }

    if needs_recompile(input, &cc_file) {
        Command::new("bison").args(&args).output().expect(&format!(
            "unable generate {} with bison",
            cc_file.to_str().unwrap()
        ));
    }

    (cc_file, header_file)
}

fn generate_with_flex() -> Vec<PathBuf> {
    let mut out_paths = vec![];

    for src in SLEIGH_FLEX.iter() {
        let path = Path::new("cpp").join(src);
        out_paths.push(run_lex(&path));
    }

    out_paths
}

fn generate_with_bison() -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut cc_paths = vec![];
    let mut header_paths = vec![];

    for src in DECOMPILER_YACC.iter() {
        let path = Path::new("cpp").join(src);
        let (cc_path, header_path) = run_bison(&path, false, true);

        cc_paths.push(cc_path);
        header_paths.push(header_path);
    }

    (cc_paths, header_paths)
}

fn prepare() -> CompileOptions {
    let mut objects = vec![];
    let mut sources = vec![];
    let includes = vec![];

    /*

    // TODO: add feature to detect if we should use flex and bison
    // to generate the code on the fly

    for src in generate_with_flex() {
        let out_path = output_path(&src, "o");
        if needs_recompile(&src, &out_path) {
            sources.push(src);
        } else {
            objects.push(out_path);
        }
    }

    let (cc_files, includes) = generate_with_bison();
    for src in cc_files {
        let out_path = output_path(&src, "o");
        if needs_recompile(&src, &out_path) {
            sources.push(src);
        } else {
            objects.push(out_path);
        }
    }

    */

    for src in DECOMPILER_SOURCE_BASE_CXX.iter() {
        let path = Path::new("cpp").join(src);
        let out_path = output_path(&path, "o");
        if needs_recompile(&path, &out_path) {
            sources.push(path);
        } else {
            objects.push(out_path);
        }
    }

    #[cfg(debug_assertions)]
    {
        for src in CLI_CXX.iter() {
            let path = Path::new("cpp").join(src);
            let out_path = output_path(&path, "o");
            if needs_recompile(&path, &out_path) {
                sources.push(path);
            } else {
                objects.push(out_path);
            }
        }
    }

    CompileOptions {
        sources,
        objects,
        includes,
    }
}

fn main() {
    let compile_opts = prepare();
    let sleigh_src_file = Path::new("src").join("bridge.rs");

    let mut target = cxx_build::bridge(sleigh_src_file);

    for obj in &compile_opts.objects {
        target.object(obj);
    }
    let bridge_path = Path::new("cpp").join("bridge.cc");
    #[cfg(target_os = "windows")]
    {
        target.define("_WINDOWS", "1"); // This is assumed by ghidra, but not defined by msvc, strange.
    }
    #[cfg(debug_assertions)]
    {
        target.define("__TERMINAL__", "");
    }
    target
        .cpp(true)
        .warnings(false)
        .file(bridge_path)
        .files(compile_opts.sources)
        .flag_if_supported("-std=c++14")
        .include("cpp")
        .includes(compile_opts.includes)
        .compile("decompile");
    #[cfg(debug_assertions)]
    println!("cargo:rustc-link-lib=bfd");
}
