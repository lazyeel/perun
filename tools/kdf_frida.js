// Frida script: KDF planter fill interceptor
// Watches the [rbp-0x38] stack slot AND the planter buffer region.
// Runs in-process — no ptrace, no hardware WPs, immune to gdb bugs.

// Stage A: hook vdfut768ig entry, wait for transform opcode
var vdfut_offset = 0x87550; // RVA of vdfut768ig in libCoreADI.so
var post_prologue_offset = 0x87565;
var base = null;

// Find libCoreADI base
Process.enumerateModules().forEach(function(m) {
    if (m.name.indexOf("libCoreADI") >= 0) {
        base = m.base;
        send({tag: "base", base: base.toString()});
    }
});

if (!base) {
    send({tag: "error", msg: "libCoreADI not found"});
} else {
    // Watch the transform entry
    Interceptor.attach(base.add(0x87554), {
        onEnter: function(args) {
            var opcode = args[0].toInt32() & 0xFFFFFFFF;
            if (opcode === 0x716bd86c) {
                var rbp = this.context.rbp;
                var slot = rbp.sub(0x38);
                send({tag: "transform", rbp: rbp.toString(), slot: slot.toString()});
                
                // Watch the slot [rbp-0x38] for writes
                var slotAddr = slot;
                MemoryAccessMonitor.enable(slotAddr, {
                    onAccess: function(details) {
                        if (details.operation === 'write') {
                            var planter = details.address.readPointer();
                            send({tag: "slot_write", from: details.from.toString(), 
                                  planter: planter.toString()});
                            MemoryAccessMonitor.disable();
                            
                            // Now watch the planter buffer's first s-box window
                            try {
                                var sbox = planter.add(0xD60);
                                var pre = sbox.readU32();
                                send({tag: "sbox_pre", addr: sbox.toString(), val: pre});
                                
                                // Watch first 8 bytes of fam1 window
                                MemoryAccessMonitor.enable(sbox, {
                                    onAccess: function(d2) {
                                        if (d2.operation === 'write') {
                                            send({tag: "kdf_write", from: d2.from.toString(),
                                                  addr: d2.address.toString(),
                                                  val: d2.address.readU32()});
                                            MemoryAccessMonitor.disable();
                                            // Dump full planter
                                            try {
                                                var dump = planter.readByteArray(0x2700);
                                                send({tag: "planter_dump"}, dump);
                                            } catch(e) {
                                                send({tag: "dump_err", msg: e.toString()});
                                            }
                                        }
                                    }
                                });
                            } catch(e) {
                                send({tag: "sbox_err", msg: e.toString()});
                            }
                        }
                    }
                });
            }
        }
    });
    send({tag: "armed", msg: "planter interceptor ready"});
}