//! JNI glue for the Android shell — `Java_tech_airdrop4e_A4eCore_*` exports
//! that marshal between Kotlin objects and the C ABI in this crate.
//! Contract: shells/ffi.md §7 (style a: direct `Java_*` exports).
#![allow(non_snake_case)]

use crate::{
    a4e_browse, a4e_identity_load_or_create, a4e_last_error, a4e_receiver_start, a4e_receiver_stop,
    a4e_send_files, a4e_string_free, A4eAsk, A4eSendOpts,
};
use jni::objects::{GlobalRef, JByteArray, JObject, JObjectArray, JString, JValue};
use jni::sys::{jint, jobject, jobjectArray, jstring, JNI_VERSION_1_6};
use jni::{JNIEnv, JavaVM};
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::ptr;
use std::sync::{Mutex, OnceLock};

static VM: OnceLock<JavaVM> = OnceLock::new();

#[no_mangle]
pub extern "system" fn JNI_OnLoad(vm: *mut jni::sys::JavaVM, _: *mut c_void) -> jint {
    if let Ok(vm) = unsafe { JavaVM::from_raw(vm) } {
        let _ = VM.set(vm);
    }
    JNI_VERSION_1_6
}

// ------------------------------------------------------------ helpers

fn jstr_opt(env: &mut JNIEnv, s: jstring) -> Option<String> {
    if s.is_null() {
        return None;
    }
    let js = unsafe { JString::from_raw(s) };
    env.get_string(&js).ok().map(|j| j.into())
}

fn jstr(env: &mut JNIEnv, s: jstring) -> String {
    jstr_opt(env, s).unwrap_or_default()
}

fn c_opt(s: Option<String>) -> Option<CString> {
    s.map(|v| CString::new(v).unwrap_or_default())
}

fn throw(env: &mut JNIEnv, msg: &str) {
    let _ = env.throw_new("tech/airdrop4e/A4eException", msg);
}

/// Convert a `char *` error out-param (or last_error) into a message and free it.
unsafe fn take_err(err: *mut c_char) -> String {
    if !err.is_null() {
        let s = CStr::from_ptr(err).to_string_lossy().into_owned();
        a4e_string_free(err);
        s
    } else {
        let p = a4e_last_error();
        if p.is_null() {
            "unknown error".to_string()
        } else {
            CStr::from_ptr(p).to_string_lossy().into_owned()
        }
    }
}

/// C string field → &str ("" for NULL).
unsafe fn fstr<'a>(p: *const c_char) -> &'a str {
    if p.is_null() {
        return "";
    }
    CStr::from_ptr(p).to_str().unwrap_or("")
}

// ------------------------------------------------------------ identity

#[no_mangle]
pub extern "system" fn Java_tech_airdrop4e_A4eCore_identityLoadOrCreate(
    mut env: JNIEnv,
    _this: JObject,
    keys_dir: jstring,
    computer_name: jstring,
) {
    let kdir = c_opt(jstr_opt(&mut env, keys_dir));
    let name = c_opt(jstr_opt(&mut env, computer_name));
    let mut err: *mut c_char = ptr::null_mut();
    let r = a4e_identity_load_or_create(
        kdir.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
        name.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
        &mut err,
    );
    if r != 0 {
        let msg = unsafe { take_err(err) };
        throw(&mut env, &msg);
    }
}

// ------------------------------------------------------------ receiver

struct AskCtx {
    handler: GlobalRef,
}

// The receiver's AskHandler global ref — freed on receiverStop.
static ASK_CTX: Mutex<Option<Box<AskCtx>>> = Mutex::new(None);

/// Build `tech.airdrop4e.A4eAsk` from the C struct.
unsafe fn build_ask<'l>(env: &mut JNIEnv<'l>, ask: &A4eAsk) -> jni::errors::Result<JObject<'l>> {
    let files = env.new_object_array(
        ask.files_len as i32,
        "tech/airdrop4e/A4eFileMeta",
        JObject::null(),
    )?;
    for i in 0..ask.files_len {
        let f = &*ask.files.add(i);
        let name = env.new_string(fstr(f.name))?;
        let uti = env.new_string(fstr(f.uti))?;
        let o = env.new_object(
            "tech/airdrop4e/A4eFileMeta",
            "(Ljava/lang/String;Ljava/lang/String;J)V",
            &[
                JValue::from(&name),
                JValue::from(&uti),
                JValue::Long(f.size as i64),
            ],
        )?;
        env.set_object_array_element(&files, i as i32, o)?;
    }
    let sn = env.new_string(fstr(ask.sender_name))?;
    let sm = env.new_string(fstr(ask.sender_model))?;
    let tid = env.new_string(fstr(ask.transfer_id))?;
    env.new_object(
        "tech/airdrop4e/A4eAsk",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ltech/airdrop4e/A4eFileMeta;)V",
        &[
            JValue::from(&sn),
            JValue::from(&sm),
            JValue::from(&tid),
            JValue::from(&files),
        ],
    )
}

unsafe extern "C" fn ask_cb(ctx: *mut c_void, ask: *const A4eAsk) -> c_int {
    let actx = &*(ctx as *const AskCtx);
    let Some(vm) = VM.get() else { return 0 };
    let Ok(mut guard) = vm.attach_current_thread() else {
        return 0;
    };
    let env = &mut *guard;
    let Some(ask) = ask.as_ref() else { return 0 };
    match build_ask(env, ask).and_then(|obj| {
        env.call_method(
            actx.handler.as_obj(),
            "onAsk",
            "(Ltech/airdrop4e/A4eAsk;)Z",
            &[JValue::from(&obj)],
        )
    }) {
        Ok(v) => v.z().unwrap_or(false) as c_int,
        Err(_) => {
            let _ = env.exception_clear();
            0
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_tech_airdrop4e_A4eCore_receiverStart(
    mut env: JNIEnv,
    _this: JObject,
    name: jstring,
    model: jstring,
    dest_dir: jstring,
    visibility: jint,
    port: jint,
    handler: jobject,
) {
    let name_c = c_opt(jstr_opt(&mut env, name));
    let model_c = c_opt(jstr_opt(&mut env, model));
    let dest_c = CString::new(jstr(&mut env, dest_dir)).unwrap_or_default();
    let (cb, ctx) = if handler.is_null() {
        (None, ptr::null_mut())
    } else {
        let handler_obj = unsafe { JObject::from_raw(handler) };
        match env.new_global_ref(&handler_obj) {
            Ok(g) => {
                let b = Box::new(AskCtx { handler: g });
                let ctx = &*b as *const AskCtx as *mut c_void;
                // the static keeps the AskCtx (and its GlobalRef) alive until
                // receiverStop — the callback derefs ctx only while serving
                *ASK_CTX.lock().unwrap() = Some(b);
                (
                    Some(ask_cb as unsafe extern "C" fn(*mut c_void, *const A4eAsk) -> c_int),
                    ctx,
                )
            }
            Err(_) => {
                throw(&mut env, "failed to pin ask handler");
                return;
            }
        }
    };
    let r = a4e_receiver_start(
        name_c.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
        model_c.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
        dest_c.as_ptr(),
        visibility,
        port as u16,
        cb,
        ctx,
    );
    if r != 0 {
        // a4e_receiver_start failed — unpin the handler if we pinned one
        if !ctx.is_null() {
            *ASK_CTX.lock().unwrap() = None;
        }
        let msg = unsafe { take_err(ptr::null_mut()) };
        throw(&mut env, &msg);
    }
}

#[no_mangle]
pub extern "system" fn Java_tech_airdrop4e_A4eCore_receiverStop(_env: JNIEnv, _this: JObject) {
    a4e_receiver_stop();
    // Drop the pinned handler (GlobalRef::drop detaches via the cached VM).
    *ASK_CTX.lock().unwrap() = None;
}

// ------------------------------------------------------------ sender

/// Read `tech.airdrop4e.A4eSendOpts` fields into the C struct.
unsafe fn read_opts(env: &mut JNIEnv, obj: &JObject) -> jni::errors::Result<A4eSendOpts> {
    let str_field = |env: &mut JNIEnv, name: &str| -> jni::errors::Result<Option<String>> {
        let v = env.get_field(obj, name, "Ljava/lang/String;")?;
        match v.l() {
            Ok(o) if !o.is_null() => {
                let js = JString::from(o);
                let s = env.get_string(&js)?;
                Ok(Some(s.into()))
            }
            _ => Ok(None),
        }
    };
    let name = str_field(env, "computerName")?;
    let model = str_field(env, "computerModel")?;
    let sid = str_field(env, "serviceId")?;
    let has_tag = env.get_field(obj, "hasAuthTag", "Z")?.z()? as i32;
    let tag_arr = env.get_field(obj, "authTag", "[B")?.l()?;
    let mut tag = [0u8; 3];
    if !tag_arr.is_null() {
        let bytes: JByteArray = tag_arr.into();
        let v = env.convert_byte_array(bytes)?;
        for (i, b) in v.iter().take(3).enumerate() {
            tag[i] = *b;
        }
    }
    let timeout = env.get_field(obj, "askTimeoutMs", "J")?.j()? as u64;
    // The C strings below leak into the opts struct; sendFiles reclaims
    // them with reclaim_str once a4e_send_files returns.
    let name = CString::new(name.unwrap_or_default()).unwrap_or_default();
    let model = CString::new(model.unwrap_or_default()).unwrap_or_default();
    let sid = CString::new(sid.unwrap_or_default()).unwrap_or_default();
    Ok(A4eSendOpts {
        struct_size: std::mem::size_of::<A4eSendOpts>() as u32,
        computer_name: if name.as_bytes().is_empty() {
            ptr::null()
        } else {
            name.into_raw()
        },
        computer_model: if model.as_bytes().is_empty() {
            ptr::null()
        } else {
            model.into_raw()
        },
        service_id: if sid.as_bytes().is_empty() {
            ptr::null()
        } else {
            sid.into_raw()
        },
        has_auth_tag: has_tag,
        auth_tag: tag,
        ask_timeout_ms: timeout,
    })
}

#[no_mangle]
pub extern "system" fn Java_tech_airdrop4e_A4eCore_sendFiles(
    mut env: JNIEnv,
    _this: JObject,
    paths: jobjectArray,
    addr: jstring,
    opts: jobject,
) {
    let vm_paths = unsafe { JObjectArray::from_raw(paths) };
    let Ok(n) = env.get_array_length(&vm_paths) else {
        throw(&mut env, "paths: bad array");
        return;
    };
    let mut keep: Vec<CString> = Vec::with_capacity(n as usize);
    let mut ptrs: Vec<*const c_char> = Vec::with_capacity(n as usize);
    for i in 0..n {
        let Ok(obj) = env.get_object_array_element(&vm_paths, i) else {
            throw(&mut env, "paths: unreadable element");
            return;
        };
        let js = JString::from(obj);
        let s: String = match env.get_string(&js) {
            Ok(s) => s.into(),
            Err(_) => {
                throw(&mut env, "paths: element is not a string");
                return;
            }
        };
        keep.push(CString::new(s).unwrap_or_default());
    }
    for c in &keep {
        ptrs.push(c.as_ptr());
    }
    let addr_c = CString::new(jstr(&mut env, addr)).unwrap_or_default();
    let opts_c = if opts.is_null() {
        ptr::null()
    } else {
        match unsafe { read_opts(&mut env, &JObject::from_raw(opts)) } {
            Ok(o) => Box::into_raw(Box::new(o)),
            Err(_) => {
                throw(&mut env, "opts: could not read A4eSendOpts");
                return;
            }
        }
    };
    let mut err: *mut c_char = ptr::null_mut();
    let r = a4e_send_files(ptrs.as_ptr(), ptrs.len(), addr_c.as_ptr(), opts_c, &mut err);
    // free the opts strings we allocated in read_opts
    if !opts_c.is_null() {
        let o = unsafe { Box::from_raw(opts_c as *mut A4eSendOpts) };
        unsafe {
            reclaim_str(o.computer_name);
            reclaim_str(o.computer_model);
            reclaim_str(o.service_id);
        }
    }
    if r != 0 {
        let msg = unsafe { take_err(err) };
        throw(&mut env, &msg);
    }
}

unsafe fn reclaim_str(p: *const c_char) {
    if !p.is_null() {
        drop(CString::from_raw(p as *mut c_char));
    }
}

// ------------------------------------------------------------ browse

#[no_mangle]
pub extern "system" fn Java_tech_airdrop4e_A4eCore_browse(
    mut env: JNIEnv,
    _this: JObject,
    timeout_ms: jint,
    cb: jobject,
) {
    if cb.is_null() {
        throw(&mut env, "PeerCallback required");
        return;
    }
    let cb_obj = unsafe { JObject::from_raw(cb) };
    let cb_ref = match env.new_global_ref(&cb_obj) {
        Ok(g) => g,
        Err(_) => {
            throw(&mut env, "failed to pin peer callback");
            return;
        }
    };
    let vm = match env.get_java_vm() {
        Ok(v) => v,
        Err(_) => {
            throw(&mut env, "no JavaVM");
            return;
        }
    };
    let _ = VM.set(vm);
    let boxed = Box::new(cb_ref);
    let ctx = Box::into_raw(boxed) as *mut c_void;
    let r = a4e_browse(timeout_ms as u32, Some(peer_cb), ctx);
    unsafe { drop(Box::from_raw(ctx as *mut GlobalRef)) };
    if r != 0 {
        let msg = unsafe { take_err(ptr::null_mut()) };
        throw(&mut env, &msg);
    }
}

unsafe extern "C" fn peer_cb(ctx: *mut c_void, peer: *const crate::A4ePeer) {
    let g = &*(ctx as *const GlobalRef);
    let Some(vm) = VM.get() else { return };
    let Ok(mut guard) = vm.attach_current_thread() else {
        return;
    };
    let env = &mut *guard;
    let Some(p) = peer.as_ref() else { return };
    let r = (|| -> jni::errors::Result<()> {
        let ident = env.new_string(fstr(p.ident))?;
        let name = if p.name.is_null() {
            JObject::null()
        } else {
            env.new_string(fstr(p.name))?.into()
        };
        let addr = env.new_string(fstr(p.addr))?;
        let obj = env.new_object(
            "tech/airdrop4e/A4ePeer",
            "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V",
            &[
                JValue::from(&ident),
                JValue::from(&name),
                JValue::from(&addr),
                JValue::Int(p.port as i32),
            ],
        )?;
        env.call_method(
            g.as_obj(),
            "onPeer",
            "(Ltech/airdrop4e/A4ePeer;)V",
            &[JValue::from(&obj)],
        )?;
        Ok(())
    })();
    if r.is_err() {
        let _ = env.exception_clear();
    }
}

// ------------------------------------------------------------ misc

#[no_mangle]
pub extern "system" fn Java_tech_airdrop4e_A4eCore_lastError(
    env: JNIEnv,
    _this: JObject,
) -> jstring {
    let p = a4e_last_error();
    if p.is_null() {
        return ptr::null_mut();
    }
    let s = unsafe { CStr::from_ptr(p) }.to_string_lossy();
    env.new_string(s.as_ref())
        .map(|j| j.into_raw())
        .unwrap_or(ptr::null_mut())
}
