use std::ptr;

const OK: i32 = 0;
const INVALID_ARGUMENT: i32 = -1;
const UNSUPPORTED_OBJECT: i32 = -2;
const BUFFER_TOO_SMALL: i32 = -6;
const CAPABILITIES: &[u8] = br#"{"schema":"candy-core-cloud-capabilities-v1","abi_version":1,"module_version":"test-1","library":"libcandy_core_cloud.so","wire_protocol":"0.3","build_request_schema":"candy-core-cloud-build-v1","max_build_request_bytes":8388608,"operations":["capabilities","canonicalize","prepare","assemble","route-content-hash","validate"],"objects":["grant-payload-v1"]}"#;

#[no_mangle]
pub extern "C" fn candy_core_cloud_abi_version() -> u32 {
    1
}

#[no_mangle]
pub unsafe extern "C" fn candy_core_cloud_capabilities(
    output: *mut u8,
    capacity: usize,
    output_len: *mut usize,
) -> i32 {
    copy_output(CAPABILITIES, output, capacity, output_len)
}

#[no_mangle]
pub unsafe extern "C" fn candy_core_cloud_canonicalize(
    object_type: u32,
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    capacity: usize,
    output_len: *mut usize,
) -> i32 {
    if object_type != 1 {
        return UNSUPPORTED_OBJECT;
    }
    if input.is_null() || input_len == 0 {
        return INVALID_ARGUMENT;
    }
    let input = std::slice::from_raw_parts(input, input_len);
    copy_output(input, output, capacity, output_len)
}

#[no_mangle]
pub unsafe extern "C" fn candy_core_cloud_prepare(
    request: *const u8,
    request_len: usize,
    object_type: *mut u32,
    payload: *mut u8,
    payload_capacity: usize,
    payload_len: *mut usize,
    transcript: *mut u8,
    transcript_capacity: usize,
    transcript_len: *mut usize,
) -> i32 {
    if request.is_null() || request_len == 0 || object_type.is_null() {
        return INVALID_ARGUMENT;
    }
    let request = std::slice::from_raw_parts(request, request_len);
    ptr::write(object_type, 1);
    let payload_status = copy_output(request, payload, payload_capacity, payload_len);
    let transcript_status = copy_output(request, transcript, transcript_capacity, transcript_len);
    if payload_status == OK && transcript_status == OK {
        OK
    } else if payload_status == BUFFER_TOO_SMALL && transcript_status == BUFFER_TOO_SMALL {
        BUFFER_TOO_SMALL
    } else {
        INVALID_ARGUMENT
    }
}

#[no_mangle]
pub unsafe extern "C" fn candy_core_cloud_assemble(
    object_type: u32,
    signing_key_id: *const u8,
    signing_key_id_len: usize,
    payload: *const u8,
    payload_len: usize,
    signature: *const u8,
    signature_len: usize,
    output: *mut u8,
    output_capacity: usize,
    output_len: *mut usize,
) -> i32 {
    if object_type != 1
        || signing_key_id.is_null()
        || signing_key_id_len == 0
        || payload.is_null()
        || payload_len == 0
        || signature.is_null()
        || signature_len != 64
    {
        return INVALID_ARGUMENT;
    }
    let signing_key_id = std::slice::from_raw_parts(signing_key_id, signing_key_id_len);
    let payload = std::slice::from_raw_parts(payload, payload_len);
    let signature = std::slice::from_raw_parts(signature, signature_len);
    let mut envelope = Vec::with_capacity(signing_key_id_len + payload_len + signature_len);
    envelope.extend_from_slice(signing_key_id);
    envelope.extend_from_slice(payload);
    envelope.extend_from_slice(signature);
    copy_output(&envelope, output, output_capacity, output_len)
}

#[no_mangle]
pub unsafe extern "C" fn candy_core_cloud_route_content_hash(
    object_type: u32,
    _input: *const u8,
    _input_len: usize,
    output_hash: *mut u8,
    output_hash_len: usize,
) -> i32 {
    if object_type != 0x101 || output_hash.is_null() || output_hash_len != 32 {
        return INVALID_ARGUMENT;
    }
    ptr::write_bytes(output_hash, 0, 32);
    OK
}

#[no_mangle]
pub unsafe extern "C" fn candy_core_cloud_validate(
    object_type: u32,
    input: *const u8,
    input_len: usize,
    key: *const u8,
    key_len: usize,
) -> i32 {
    if object_type != 1 {
        return UNSUPPORTED_OBJECT;
    }
    if input.is_null() || input_len == 0 || !key.is_null() || key_len != 0 {
        return INVALID_ARGUMENT;
    }
    OK
}

unsafe fn copy_output(
    value: &[u8],
    output: *mut u8,
    capacity: usize,
    output_len: *mut usize,
) -> i32 {
    if output_len.is_null() {
        return INVALID_ARGUMENT;
    }
    ptr::write(output_len, value.len());
    if output.is_null() && capacity == 0 {
        return BUFFER_TOO_SMALL;
    }
    if output.is_null() || capacity < value.len() {
        return BUFFER_TOO_SMALL;
    }
    ptr::copy_nonoverlapping(value.as_ptr(), output, value.len());
    OK
}
