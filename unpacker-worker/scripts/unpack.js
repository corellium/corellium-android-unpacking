console.log("[*] Android Version : " + Java.androidVersion);

// One of the few times in my life I've ever used a < on a string... but it works?
if(Java.androidVersion <  "7.1.2") {
    console.log("[!] Unsupported Android version, expected 7.2, this likely won't work!");
}

var libart = "libart.so"
var openMemory_7_1_2 = "_ZN3art7DexFile10OpenMemoryEPKhmRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileEPS9_";
var openMemory_libArt_ptr = Module.findExportByName(libart, openMemory_7_1_2);

var package_name = null;

function getPackageName() {
    if(Java.available) {
        Java.perform(function() {
            var activityThread = Java.use("android.app.ActivityThread");
            package_name = activityThread.currentProcessName();
            console.log("[+] Found target package name : " + package_name);
        });
    }
}

function sendDex(address) {
    try {
        var dex_size = Memory.readU32(address.add(0x20));
        send("dex", Memory.readByteArray(address, dex_size));
    } catch (e) {
        console.log("[!] Exception in sendDex", e);
    }
};

if(openMemory_libArt_ptr != null) {
    Interceptor.attach(openMemory_libArt_ptr, {
        onEnter: function (args) {

            // Nothing outside of base is used by the rest of the script, however it can
            // be useful for debugging
            var base = args[0];
            var size = args[1].toInt32();
            var location = args[2];
            var location_checksum = args[3].toInt32();
            var memMap = args[4];
            var errorMsg = args[5];
            console.log("[*] art::DexFile::openMemory :", base, ":", size, ":", Memory.readUtf8String(location), ":", location_checksum, ":", memMap, ":", errorMsg);
    
            console.log(hexdump(base, {
                offset: 0,
                length: 0xF,
                header: true,
                ansi: true
              }));

              sendDex(base);
        },
        onLeave: function (retval) {
            // No need to do anything...
        }
    });
} else {
    console.log("Failed to find correct function to hook in libart!");
}